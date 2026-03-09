# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

load("//bazel:mongo_src_rules.bzl", "mongo_cc_library")

package(default_visibility = ["//visibility:public"])

mongo_cc_library(
    name = "prometheus_exporter_utils",
    srcs = [
        "src/exporter_utils.cc",
    ],
    hdrs = [
        "include/opentelemetry/exporters/prometheus/exporter_utils.h",
    ],
    strip_include_prefix = "include",
    tags = ["prometheus"],
    deps = [
        "//src/third_party/opentelemetry-cpp/api",
        "//src/third_party/opentelemetry-cpp/sdk:headers",
        "@com_github_jupp0r_prometheus_cpp//core",
    ],
)
