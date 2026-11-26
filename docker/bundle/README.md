Put `gapscan-bundle.tar.gz` here to build the image from a verified offline bundle
(`make docker-build BUNDLE=...` copies it for you). The folder must exist even when the image is built
with `DATA_SOURCE=fetch` or `none`, because the Dockerfile mounts it.
