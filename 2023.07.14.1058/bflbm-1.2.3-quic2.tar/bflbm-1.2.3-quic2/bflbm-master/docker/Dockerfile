ARG OS_VER=11.7
ARG KERNEL_VER=5.10.0-23
FROM debian:${OS_VER}
LABEL maintainer="anton@skorochod.cz"

WORKDIR /

# Install prerequisite packages
ARG KERNEL_VER
RUN apt-get update && apt-get install -y \
    libmnl-dev libnuma-dev numactl libnuma1 libjansson-dev \
    unzip wget make gcc ethtool net-tools git \
    lsb-base udev libnl-3-200 libnl-route-3-200 \
    build-essential bzip2 dirmngr distro-info-data dkms dpkg-dev fakeroot file \
    g++ g++-8 gnupg gnupg-l10n gnupg-utils gpg gpg-agent gpg-wks-client \
    gpg-wks-server gpgconf gpgsm kmod libalgorithm-diff-perl \
    libalgorithm-diff-xs-perl libalgorithm-merge-perl libassuan0 libdpkg-perl \
    libfakeroot libfile-fcntllock-perl libgpm2 libksba8 liblocale-gettext-perl \
    libmagic-mgc libmagic1 libnpth0 libpci3 libsqlite3-0 linux-headers-${KERNEL_VER}-amd64 lsb-release lsof \
    mime-support pinentry-curses procps psmisc readline-common sudo xz-utils \
    swig automake graphviz m4 libltdl-dev quilt autotools-dev \
    debhelper chrpath libnl-3-dev dpatch libnl-route-3-dev autoconf \
    meson pkg-config
