#! /usr/bin/env python3
"""
OIDC Identity Provider Server Mock
"""
import argparse
import logging
import os
import time
import json
import http.server
import ssl
import threading
import signal
from urllib.parse import urljoin, urlparse, parse_qsl
import base64
import hashlib

from typing import Tuple, Dict, Callable
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from datetime import datetime, timedelta, timezone
from jwt import encode as jwt_encode
from jwt import decode as jwt_decode
from jwt import ExpiredSignatureError, InvalidTokenError
from jwt.api_jwt import decode_complete as jwt_decode_complete

logger = logging.getLogger(os.path.splitext(os.path.basename(__file__))[0])


def fatal(msg: str):
    """
    Log a fatal error message and exit the program.
    Args:
        msg (str): The error message to log.
    """
    logger.critical(msg)
    exit(1)


def log_pretty_json(log, title: str, json_obj: Dict):
    """
    Log a JSON object in a pretty format.
    Args:
        log (function): The logging function to use.
        title (str): The title to log.
        json_obj (dict): The JSON object to log.
    """
    try:
        json_str = title + " " + json.dumps(json_obj, indent=2)
        for line in json_str.splitlines():
            log(line)
    except TypeError as e:
        logger.error(f"Failed to serialize JSON: {e}")

@dataclass
class TokenParams:
    """
    Class to hold token parameters.
    """

    private_key: RSAPrivateKey
    payload: Dict
    key_id: int
    kid: str
    expires_in_seconds: int
    faults: Dict[str, any]
    introspection: Dict[str, any]


class JWFactory:
    """
    Class to create and manage JSON Web Keys (JWKs) and JSON Web Tokens (JWTs).
    """

    def __init__(
        self,
        common_name: str,
        issuer_url: str,
        number_of_keys: int,
        token_config,
    ):
        self.token_config = token_config
        self.number_of_keys = number_of_keys
        self.key_size = 2048
        self.algorithm = "RS256"
        self.common_name = common_name
        self.issuer_url = issuer_url
        self.keys = []

    def create_private_key(self) -> RSAPrivateKey:
        """
        Generate a new RSA private key.
        Returns:
            RSAPrivateKey: The generated private key.
        """
        return rsa.generate_private_key(public_exponent=65537, key_size=self.key_size)

    def generate_self_signed_jwk(self) -> Tuple[Dict, RSAPrivateKey]:
        """
        Generate a self-signed JWK (JSON Web Key) and its corresponding private key.
        Returns:
            Tuple[Dict, RSAPrivateKey]: The generated JWK and private key.
        """

        # Base64 URL-safe encoding without padding.
        def b64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

        # Convert an integer to bytes.
        def toBytes(n: int) -> bytes:
            return n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")

        # Generate a new RSA private key.
        # The private key is used to sign the certificate and the JWK.
        private_key = self.create_private_key()

        # Create a self-signed certificate.
        name_attr = x509.NameAttribute(x509.NameOID.COMMON_NAME, self.common_name)
        name = x509.Name([name_attr])
        not_valid_before = datetime.now(timezone.utc)
        not_valid_after = not_valid_before + timedelta(days=365)
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
        )
        cert = cert_builder.sign(private_key, hashes.SHA256(), default_backend())

        # Get the public key and its numbers.
        public_key = cert.public_key()
        public_numbers = public_key.public_numbers()
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        # Generate a kid from the SHA-256 thumbprint
        # RFC 7638, Section 3
        jwk = {
            "e": b64url(toBytes(public_numbers.e)),
            "kty": "RSA",
            "n": b64url(toBytes(public_numbers.n)),
        }
        jwk_buf = json.dumps(jwk, separators=(",", ":")).encode("utf-8")
        kid = b64url(hashlib.sha256(jwk_buf).digest())

        # Create the JWK (RFC 7517)
        jwk.update(
            {
                "use": "sig",  # RFC 7517, Section 4.2
                "alg": self.algorithm,  # RFC 7517, Section 4.4
                "kid": kid,  # RFC 7517, Section 4.5
                "x5c": [
                    base64.b64encode(cert_der).decode("ascii")
                ],  # RFC 7517, Section 4.7
                "x5t": b64url(hashlib.sha1(cert_der).digest()),  # RFC 7517, Section 4.8
                "x5t#S256": b64url(
                    hashlib.sha256(cert_der).digest()
                ),  # RFC 7517, Section 4.9
            }
        )

        # Return the JWK and private key.
        return jwk, private_key

    def create_jwks(self):
        """
        Create a set of JWKs (JSON Web Keys) for the issuer.
        """
        self.keys = []
        for _ in range(self.number_of_keys):
            jwk, private_key = self.generate_self_signed_jwk()
            log_pretty_json(logger.debug, f"Created JWK[{len(self.keys)}]: ", jwk)
            self.keys.append(
                {
                    "private_key": private_key,
                    "jwk": jwk,
                }
            )

    def get_jwks(self) -> Dict:
        """
        Get the JWKs (JSON Web Keys) for the issuer.
        Returns:
            dict: The JWKs.
        """
        dict = {
            "keys": [],
        }
        for key in self.keys:
            dict["keys"].append(key["jwk"])

        return dict

    def get_token_params(self) -> TokenParams:
        """
        Get the token parameters for the issuer.
        This method returns the parameters to create a JWT based on the provided token_config in the constructor.
        Returns:
            TokenParams: The token parameters. None if no more token_config is provided.
        """

        # Return None if no token_config is provided
        if self.token_config is None:
            return None

        token_config = {}
        # If token_config is a list, pop the first element.
        # If token_config is a dict, use it as is.
        if isinstance(self.token_config, list):
            if len(self.token_config) == 0:
                logger.warning("No tokens available")
                return None
            token_config = self.token_config.pop(0)
        else:
            token_config = self.token_config

        expires_in_seconds = token_config.get("expires_in_seconds", 3600)
        key_id = token_config.get("key_id", 0)
        payload = token_config.get("payload")

        def set_default_value(payload, key, value):
            if key not in payload:
                payload[key] = value
            elif payload[key] == "$remove":
                del payload[key]

        if payload is not {}:
            set_default_value(payload, "iat", int(time.time()))
            set_default_value(payload, "iss", self.issuer_url)
            set_default_value(payload, "exp", int(time.time()) + expires_in_seconds)

        return TokenParams(
            payload=payload,
            key_id=key_id,
            expires_in_seconds=expires_in_seconds,
            kid=self.get_kid(key_id),
            private_key=self.get_private_key(key_id),
            faults=token_config.get("faults"),
            introspection=token_config.get("introspection"),
        )

    def get_private_key(self, key_id) -> RSAPrivateKey:
        """
        Get the private key for the specified key ID.
        Args:
            key_id (int): The key ID.
        Returns:
            RSAPrivateKey: The private key.
        """
        if key_id >= len(self.keys):
            raise ValueError(
                f"invalid key_id: {key_id}, number_of_keys: {len(self.keys)}"
            )
        return self.keys[key_id]["private_key"]

    def get_kid(self, key_id) -> str:
        """
        Get the key ID (kid) for the specified key ID.
        Args:
            key_id (int): The key ID.
        Returns:
            str: The key ID (kid).
        """
        if key_id >= len(self.keys):
            raise ValueError(f"invalid key_id: {key_id}")
        return self.keys[key_id]["jwk"]["kid"]

    def create_jwt(self, params: TokenParams) -> str:
        """
        Create a JWT with the specified payload, kid, signed with provided private key.
        Args:
            private_key (RSAPrivateKey): The private key to sign the JWT.
            payload (Dict): The payload to include in the JWT.
            kid (str): The key ID (kid) to include in the JWT header, if None, it will be omitted.
        Returns:
            str: The signed JWT.
        """
        headers = {}
        if params.kid is not None:
            headers["kid"] = params.kid

        return jwt_encode(
            params.payload,
            params.private_key,
            algorithm=self.algorithm,
            headers=headers,
        )

    def decode_jwt(self, jwt: str, params: TokenParams) -> Dict:
        """
        Decode a JWT without verification, used for debugging.
        Args:
            jwt (str): The JWT to decode.
            private_key (RSAPrivateKey): The private key to use for decoding.
        Returns:
            Dict: The decoded JWT payload with headers.
        """
        try:
            options = {
                "verify_signature": False,
                "verify_aud": False,
                "verify_iat": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iss": False,
            }
            dec = jwt_decode_complete(
                jwt,
                key=params.private_key.public_key(),
                algorithms=[self.algorithm],
                options=options,
            )
            del dec["signature"]
        except Exception as e:
            return {"error": str(e)}
        return dec


class TokenFaultInjector:
    """
    Class to inject faults.
    """

    @classmethod
    def apply_params(cls, jwf: JWFactory, params: TokenParams) -> None:
        """
        Inject faults into the token parameters.
        Args:
            jwf (JWFactory): The JWFactory instance.
            params (TokenParams): Token parameters to modify.
        """

        # Set 'kid' field to invalid value
        if "jwt_invalid_kid" in params.faults:
            params.kid = "invalid_kid"
        # Omit 'kid' field
        if "jwt_missing_kid" in params.faults:
            params.kid = None
        # Use invalid private key
        if "jwt_invalid_key" in params.faults:
            params.private_key = jwf.create_private_key()
        # Use valid key but with different kid.
        if "jwt_other_valid_key" in params.faults:
            other_key_id = 1 if params.key_id == 0 else 0
            params.private_key = jwf.get_private_key(other_key_id)
            params.kid = jwf.get_kid(params.key_id)

    @classmethod
    def apply_jwt_format(cls, jwt: str, params: TokenParams) -> str:
        """
        Apply faults to the JWT format.
        Args:
            jwt (str): The JWT to modify.
            params (TokenParams): The token parameters.
        Returns:
            str: The modified JWT.
        """
        if "jwt_invalid_format" in params.faults:
            # Change the format of the JWT
            jwt = jwt.replace(".", "-")
        if "jwt_invalid_padding" in params.faults:
            # Change the padding of the JWT
            jwt = jwt + "="
        return jwt


class RequestHandler(http.server.BaseHTTPRequestHandler):
    """
    Custom request handler for handling HTTP requests.
    """

    def __init__(self, *args, url, get_handlers, post_handlers, **kwargs):
        self.url = url
        self.post_handlers = post_handlers
        self.get_handlers = get_handlers
        super().__init__(*args, **kwargs)

    def log_request(self, req: str, body: str = None):
        """
        Log the HTTP request.
        """
        msg = f"{req} {urljoin(self.url, self.path)}"
        if body is not None:
            msg = msg + f" body: {json.dumps(body)}"
        logger.debug(msg)

    def respond(self, status: int, response: str):
        """
        Send the HTTP response.
        Args:
            status (int): The HTTP status code.
            response (str): The response body.
        """
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(response)

    def try_parse_body(self):
        """
        Try to parse the body of the request.
        Returns:
            str: The parsed body as a string, or None if parsing fails.
        """
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                body = self.rfile.read(content_length)
                return body.decode("utf-8")
        except:
            logger.warning("Failed to parse body")
            return None

    def do_request(self, method: str, handlers: Dict):
        """
        Handle HTTP requests by calling the appropriate handler.
        Args:
            method (str): The HTTP method (GET or POST).
            handlers (Dict): The dictionary of registered handlers.
        """
        body = self.try_parse_body()
        self.log_request(method, body)
        status = 404
        response = {"error": "Not Found"}
        if self.path in handlers:
            handler = handlers[self.path]
            status, response = handler(body)

        self.respond(status, json.dumps(response).encode("utf-8"))

    def do_POST(self):
        """
        Handle POST requests.
        """
        self.do_request("POST", self.post_handlers)

    def do_GET(self):
        """
        Handle GET requests.
        """
        self.do_request("GET", self.get_handlers)


class IdPMock:
    """
    Class to mock an Identity Provider
    """

    HandlerReturnType = Tuple[int, bytes]
    HandlerFunctionType = Callable[[str], HandlerReturnType]

    def __init__(self, config: Dict):
        self.config = config
        self.post_handlers = {}
        self.get_handlers = {}
        self.jwf = JWFactory(
            common_name=self.config["host"],
            issuer_url=self.config["issuer_url"],
            number_of_keys=self.config["number_of_jwks"],
            token_config=self.config["token"],
        )
        self.jwf.create_jwks()
        self.jwts = {}
        self.register()

    def addr(self) -> Tuple[str, int]:
        """
        Get the address and port of the IdP server.
        Returns:
            Tuple[str, int]: The host and port of the IdP server.
        """
        return self.config["host"], self.config["port"]

    def url(self) -> str:
        """
        Get the URL of the IdP server.
        Returns:
            str: The URL of the IdP server.
        """
        return self.config["issuer_url"]

    def rel_path(self, path: str) -> str:
        """
        Create a relative path for the issuer URL.
        Args:
            path (str): The relative path to append to the issuer URL.
        Returns:
            str: The complete URL with the relative path.
        """
        # Ensure the issuer ends with a slash
        issuer = self.config["issuer_base_path"]
        if not issuer.endswith("/"):
            issuer += "/"
        if not issuer.startswith("/"):
            issuer = "/" + issuer

        # Ensure the path does not start with a slash
        if path.startswith("/"):
            path = path[1:]

        return urljoin(issuer, path)

    def post(self, path: str, handler: HandlerFunctionType):
        """
        Register a POST handler for the specified path.
        Args:
            path (str): The path to register the handler for.
            handler (HandlerFunctionType): The handler function to call for the POST request.
        """
        path = self.rel_path(path)
        if path in self.post_handlers:
            raise ValueError(f"Handler for path {path} already registered")
        logger.debug(f"Registering POST handler for '{path}'")
        self.post_handlers[path] = handler

    def get(self, path: str, handler: HandlerFunctionType):
        """
        Register a GET handler for the specified path.
        Args:
            path (str): The path to register the handler for.
            handler (HandlerFunctionType): The handler function to call for the GET request.
        """
        path = self.rel_path(path)
        if path in self.get_handlers:
            raise ValueError(f"Handler for path {path} already registered")
        logger.debug(f"Registering GET handler for '{path}'")
        self.get_handlers[path] = handler

    def create_handler(self, *args, **kwargs) -> RequestHandler:
        """
        Create a request handler for the IdP server.
        """
        return RequestHandler(
            *args,
            url=self.url(),
            get_handlers=self.get_handlers,
            post_handlers=self.post_handlers,
            **kwargs,
        )

    def register(self):
        """
        Register handlers for the IdP server.
        """
        self.get("/.well-known/openid-configuration", self.handle_configuration)
        self.get("/keys", self.handle_keys)
        self.post("/device/authorize", self.handle_device_authorize)
        self.post("/token", self.handle_token)
        self.post("/introspect", self.handle_introspect)

    def get_openid_config(self) -> Dict:
        """
        Returns OpenID configuration data.
        Returns:
            dict: The OpenID configuration.
        """
        issuer_url = self.config["issuer_url"].strip("/")
        return {
            "issuer": f"{issuer_url}",
            "token_endpoint": f"{issuer_url}/token",
            "jwks_uri": f"{issuer_url}/keys",
            "introspection_endpoint": f"{issuer_url}/introspect",
            "device_authorization_endpoint": f"{issuer_url}/device/authorize",
        }

    def handle_configuration(self, _) -> HandlerReturnType:
        """
        Handle the OpenID configuration request.
        Returns:
            HandlerReturnType: The HTTP status code and response body.
        """
        return (200, self.get_openid_config())

    def handle_keys(self, _) -> HandlerReturnType:
        """
        Handle the keys request.
        Returns:
            HandlerReturnType: The HTTP status code and response body.
        """
        return (200, self.jwf.get_jwks())

    def handle_device_authorize(self, _) -> HandlerReturnType:
        """
        Handle the device authorization request.
        Returns:
            HandlerReturnType: The HTTP status code and response body.
        """
        response = {
            "device_code": "device_code",
            "user_code": "user_code",
            "verification_uri": f"{self.url()}/device/verify",
            "expires_in": 100,
            "interval": 5,
        }

        return (200, response)

    def handle_token(self, _) -> HandlerReturnType:
        """
        Handle the token request.
        Returns:
            HandlerReturnType: The HTTP status code and response body.
        """

        # get token from factory and return error if no more tokens available
        params = self.jwf.get_token_params()
        if params is None:
            return (400, {"error": "No more tokens available"})

        # apply faults to params
        if params.faults is not None:
            TokenFaultInjector.apply_params(self.jwf, params)

        # create JWT
        jwt = self.jwf.create_jwt(params)

        # apply faults to the JWT format
        if params.faults is not None:
            jwt = TokenFaultInjector.apply_jwt_format(jwt, params)

        # cache for the introspection
        self.jwts[jwt] = params

        logger.debug(f"key_id: {params.key_id}")
        logger.debug(f"jwt: {jwt}")
        log_pretty_json(logger.debug, "JWT Payload: ", params.payload)
        log_pretty_json(logger.debug, "Decoded JWT: ", self.jwf.decode_jwt(jwt, params))

        response = {
            "access_token": jwt,
            "token_type": "Bearer",
            "expires_in": params.expires_in_seconds,
            "refresh_token": "refresh_token",
            "id_token": "",
            "scope": params.payload.get("scope", ""),
        }
        return (200, response)

    def auto_introspect_token(
        self, token: str, token_params: TokenParams
    ) -> HandlerReturnType:
        """
        Automatically introspect the token.
        Args:
            token (str): The token to introspect.
            token_params (TokenParams): The token parameters.
        Returns:
            HandlerReturnType: The HTTP status code and introspection result.
        """
        result = {"active": False}
        try:
            decoded = jwt_decode(
                token,
                key=token_params.private_key.public_key(),
                algorithms=[self.jwf.algorithm],
                audience=token_params.payload.get("aud"),
                issuer=token_params.payload.get("iss"),
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iat": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                },
            )

            if decoded:
                result = {"active": True}
                result.update(decoded)
        except ExpiredSignatureError:
            logger.info("Token expired")
        except InvalidTokenError as e:
            logger.info("Token invalid")

        return (200, result)

    def get_introspection_config(self, introspection: Dict) -> Dict:
        """
        Get the introspection configuration.
        
        If introspection is a list, pop the first element, otherwise, use it as is
        Args:
            introspection (Dict): The introspection configuration dict.
        Returns:
            Dict: The introspection configuration.
        """
        introspection_config = None
        if isinstance(introspection, list):
            if len(introspection) == 0:
                return None
            introspection_config = introspection.pop(0)
        else:
            introspection_config = introspection

        return introspection_config

    def get_introspection_result(self, introspection_config: Dict, token: str, token_params: TokenParams) -> Tuple[int, Dict]:
        """
        Get the introspection result based on the introspection configuration.

        This method handles the automatic introspection if $auto is True.
        It also applies the introspection configuration to the result.
        Args:
            introspection_config (Dict): The introspection configuration.
            token (str): The token to introspect.
            token_params (TokenParams): The token parameters.
        Returns:
            Tuple[int, Dict]: The HTTP status code and introspection result.
        """

        if introspection_config.get("$auto", False):
            # automatic introspection if $auto is True
            logger.info("Using automatic introspection")
            status_code, result = self.auto_introspect_token(token, token_params)

            # apply introspection config
            result.update(introspection_config)
        else:
            # initialize result with introspection config
            result = introspection_config.copy()
            status_code = 200

        if "$status_code" in introspection_config:
            status_code = introspection_config["$status_code"]

        def overwrite_value(payload, key, value):
            if value == "$remove":
                payload.pop(key, None)
            else:
                payload[key] = value

        # overwrite values or remove them if requested
        for key, value in introspection_config.items():
            overwrite_value(result, key, value)

        # remove special keys
        result = {k: v for k, v in result.items() if not k.startswith("$")}

        return status_code, result

    def parse_introspect_params(self, params: Dict) -> Tuple[str, str, TokenParams]:
        """
        Parse the introspection parameters from the request.
        Args:
            params (Dict): The request parameters.
        Returns:
            Tuple[str, str, TokenParams]: A tuple containing an error message (if any), the token, and the token parameters.
        """
        token = params.get("token")
        if token is None:
            return ("Missing token", None, None)

        client_id = params.get("client_id")
        if client_id is None:
            return ("Missing client_id", None, None)

        token_params = self.jwts.get(token)
        if token_params is None:
            return ("Invalid token", None, None)
        
        return (None, token, token_params)

    def handle_introspect(self, body) -> HandlerReturnType:
        """
        Handle the introspection request.
        Args:
            body (str): The request body.
        Returns:
            HandlerReturnType: The HTTP status code and introspection result.
        """
        params = dict(parse_qsl(body))

        err, token, token_params = self.parse_introspect_params(params)
        if err is not None:
            logger.warning(f"Error: {err}")
            return (400, {"error": err})

        if token_params.introspection is None:
            logger.debug("No introspection config, using automatic introspection")
            return self.auto_introspect_token(token, token_params)

        introspection_config = self.get_introspection_config(token_params.introspection)
        if introspection_config is None:
            logger.warning("No introspection config available")
            return (400, {"error": "No more introspection config available"})

        return self.get_introspection_result(introspection_config, token, token_params)


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command line argument parser.
    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description="OIDC Identity Provider Mock")
    parser.add_argument(
        "-v", "--verbose", action="count", help="enable verbose logging"
    )
    parser.add_argument(
        "--cert",
        type=str,
        required=True,
        metavar="<path>",
        help="certificate file for HTTPS",
    )
    parser.add_argument(
        "--config-json",
        type=str,
        required=False,
        metavar="{<json>}",
        help="configuration JSON",
    )
    parser.add_argument(
        "issuer_url",
        nargs="?",
        default="https://localhost:8443/issuer",
        help="issuer URL [default: https://localhost:8443/issuer]",
    )

    return parser


def parse_url(url: str) -> Tuple[str, int, str]:
    """
    Parse the issuer URL into its components.
    Args:
        url (str): The issuer URL.
    Returns:
        Tuple[str, int, str]: The hostname, port, and path of the URL.
    """
    parsed_url = urlparse(url)

    if parsed_url.scheme != "https":
        fatal("Only HTTPS is supported")
    if parsed_url.port is None:
        fatal(f"Port is required in url: {url}")
    if parsed_url.hostname is None:
        fatal(f"Hostname is required in url: {url}")

    return parsed_url.hostname, parsed_url.port, parsed_url.path


def parse_args(args):
    """
    Parse command line arguments and load configuration.
    Args:
        args (argparse.Namespace): The command line arguments.
    Returns:
        dict: The configuration dictionary.
    """
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format=f"%(asctime)s %(levelname)-5s %(module)s [{args.issuer_url}]: %(message)s",
    )
    logging.Formatter.converter = time.gmtime

    config = {}
    if args.config_json is not None:
        try:
            config = json.loads(args.config_json)
        except json.JSONDecodeError as e:
            fatal(f"Invalid JSON in config file: {e}")

    log_pretty_json(logger.debug, "Config: ", config)

    return config


def run_server(args, idp: IdPMock):
    """
    Run the IDP server.
    Args:
        args (argparse.Namespace): The command line arguments.
        idp (IdPMock): The IdPMock instance.
    """

    # Create the server and wrap it with SSL
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=args.cert)
    server = http.server.HTTPServer(idp.addr(), idp.create_handler)
    server.socket = ssl_context.wrap_socket(server.socket, server_side=True)

    def signal_handler(signum, _):
        logger.info(f"Signal {signum} received, shutting down")
        server.shutdown()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    server_ready = threading.Event()

    def serve_forever():
        server_ready.set()
        server.serve_forever()

    logger.info("Starting OIDC IDP server...")
    server_thread = threading.Thread(
        target=serve_forever, name="OIDC IDP Server Thread", daemon=True
    )

    server_thread.start()
    # make sure the log is printed after the server is ready
    server_ready.wait()
    logger.info(f"OIDC IDP server is running at {idp.url()}")

    server_thread.join()
    server.server_close()
    logger.info("OIDC IDP server closed")


def create_idp_config(args, config: Dict) -> Dict:
    """
    Create the IdP configuration.
    Args:
        args (argparse.Namespace): The command line arguments.
        config (dict): The configuration dictionary.
    Returns:
        dict: The IdP configuration dictionary.
    """
    idp_config = {}

    host, port, base_path = parse_url(args.issuer_url)

    idp_config["host"] = host
    idp_config["port"] = port
    idp_config["issuer_base_path"] = base_path
    idp_config["issuer_url"] = args.issuer_url

    idp_config["number_of_jwks"] = config.get("number_of_jwks", 1)
    idp_config["token"] = config.get("token")

    log_pretty_json(logger.debug, "IdP Config:", idp_config)

    return idp_config


def main():
    parser = build_parser()
    args = parser.parse_args()
    logger.debug(f"Certificate: {args.cert}")

    config = parse_args(args)
    idp_config = create_idp_config(args, config)

    idp = IdPMock(idp_config)

    run_server(args, idp)


if __name__ == "__main__":
    main()
