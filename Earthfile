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
    COPY go.mod .
    COPY go.sum .
    RUN go mod download
    COPY . .
    RUN go build -o ukify main.go
    SAVE ARTIFACT ukify ukify

test:
    FROM fedora
    RUN dnf install -y systemd-boot
    WORKDIR build
    COPY +uki-artifacts/kernel kernel
    COPY +uki-artifacts/initrd initrd
    COPY +build/ukify ukify
    COPY pkg/measure/pcr/testdata/private.pem private.pem
    RUN ./ukify --debug create -i initrd -k kernel -b /usr/lib/systemd/boot/efi/systemd-bootx64.efi -s /usr/lib/systemd/boot/efi/linuxx64.efi.stub -p private.pem
