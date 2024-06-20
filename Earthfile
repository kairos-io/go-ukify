VERSION 0.8


uki-artifacts:
    FROM fedora
    RUN dnf install -y kernel systemd
    ARG KERNEL=$(ls /lib/modules | head -n1)
    ARG INITRAMFS=$(ls /boot/initramfs*.img)
    RUN echo $KERNEL | sed --expression "s/vmlinuz-//g" | sed --expression "s/.fc40.x86_64//g" > /tmp/uname

    SAVE ARTIFACT /lib/modules/$KERNEL/vmlinuz kernel AS LOCAL build/kernel
    SAVE ARTIFACT /etc/os-release osrelease AS LOCAL build/osrelease
    SAVE ARTIFACT /tmp/uname uname AS LOCAL build/uname
    SAVE ARTIFACT $INITRAMFS initrd AS LOCAL build/initrd

build:
    FROM golang:1.22
    WORKDIR build
    COPY . .
    RUN go build -o ukify main.go
    SAVE ARTIFACT ukify ukify

test:
    FROM fedora
    WORKDIR build
    COPY +uki-artifacts/kernel kernel
    COPY +uki-artifacts/initrd initrd
    COPY +build/ukify ukify
    RUN ./ukify
