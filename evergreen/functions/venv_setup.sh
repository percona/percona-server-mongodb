# exit immediately if virtualenv is not found
set -o errexit

evergreen_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)/.."
. "$evergreen_dir/prelude_workdir.sh"
. "$evergreen_dir/prelude_python.sh"

python_loc=$(which ${python})
venv_dir="${workdir}/venv"
if [ -d "$venv_dir" ]; then
  exit 0
fi
"$python_loc" -m venv "$venv_dir"

# venv creates its Scripts/activate file with CLRF endings, which
# cygwin bash does not like. dos2unix it
# (See https://bugs.python.org/issue32451)
if [ "Windows_NT" = "$OS" ]; then
  dos2unix "${workdir}/venv/Scripts/activate"
fi

export VIRTUAL_ENV_DISABLE_PROMPT=yes

# Not all git get project calls clone into ${workdir}/src so we allow
# callers to tell us where the pip requirements files are.
pip_dir="${pip_dir}"
if [[ -z $pip_dir ]]; then
  # Default to most common location
  pip_dir="${workdir}/src/etc/pip"
fi

# Same as above we have to use quotes to preserve the
# Windows path separator
toolchain_txt="$pip_dir/toolchain-requirements.txt"

# the whole prelude cannot be imported because it requires pyyaml to be
# installed, which happens just below.
. "$evergreen_dir/prelude_venv.sh"

activate_venv
echo "Upgrading pip to 21.0.1"

# ref: https://github.com/grpc/grpc/issues/25082#issuecomment-778392661
if [ "$(uname -m)" = "arm64" ] && [ "$(uname)" == "Darwin" ]; then
  export GRPC_PYTHON_BUILD_SYSTEM_OPENSSL=1
  export GRPC_PYTHON_BUILD_SYSTEM_ZLIB=1
fi

python -m pip --disable-pip-version-check install "pip==21.0.1" "wheel==0.37.0" || exit 1
count=0
while :; do
  if ! python -m pip --disable-pip-version-check install -r "$toolchain_txt" -q --log install.log; then
    count=$((count + 1))
    if [[ $count < 5 ]]; then
      rand=$((1 + $RANDOM % 3))
      # delay = 20+[1-3] -> 80+[4-12] -> 180+[9-27] -> 320+[16-48]
      sleep $((count * count * (20 + rand)))
      continue
    fi
    echo "Pip install error"
    cat install.log || true
    exit 1
  else
    break
  fi
done

python -m pip freeze > pip-requirements.txt
