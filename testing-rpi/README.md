## Setting up Raspberry Pi PPS output

These instructions and patches were created and tested based on the 20211118 kernel release for raspberry pi, on a raspberry pi 3. They may or may not work with later versions of the kernel or of the raspberry pi. Note also that compiling the kernel for a raspberry pi on the device itself will take a significant ammount of time. The first time, expect it to take a couple hours.

First, install the tools needed for kernel compilation:
```bash
sudo apt install git bc bison flex libssl-dev make
```

Next, fetch the desired kernel and patch it
```bash
git clone --depth 1 --branch stable_20211118 https://github.com/raspberrypi/linux.git
cd linux
git am ../0001-pps-add-gpio-PPS-signal-generator.patch
git am ../0002-add-DT-overlay-for-pps-gen-gpio-generator.patch
git am ../0003-Updated-gpio-pps-to-work-with-timespec64.patch
```

Then configure the kernel for the raspberry pi 3 and enable pps
```bash
KERNEL=kernel7
make bcm2709_defconfig
echo 'CONFIG_PPS_GENERATOR_GPIO=y' >> .config
make olddefconfig
```

Now you are ready to build the actual kernel. This will take a while.
```bash
make -j4 zImage modules dtbs
```

Finally, install it for booting.
```bash
sudo make modules_install
sudo cp arch/arm/boot/dts/*.dtb /boot/
sudo cp arch/arm/boot/dts/overlays/*.dtb* /boot/overlays/
sudo cp arch/arm/boot/dts/overlays/README /boot/overlays/
sudo cp arch/arm/boot/zImage /boot/$KERNEL.img
```

Then, to enable the Pulse per second output on gpio pin 18, add the following line to `/boot/config.txt`:
```
dtoverlay=pps-gen-gpio
```
This adds the pps output to the device tree and ensures it is enabled.

After all this, you can reboot the pi, and it should boot with the pps enabled. This can be checked with the command
```
lsmod | grep pps
```
Which should result in a single line of output
```
pps_gen_gpio           16384  0
```
If this is shown, you should now be able to see a PPS signal on gpio pin 18.
