@echo off
cd /d "C:\ADAM_Sandbox\Adam"
echo ===================================================
echo Starting QEMU Windows 10 VM with GUI (SDL Fallback)
echo ===================================================

"C:\Program Files\qemu\qemu-system-x86_64.exe" ^
  -m 4096 ^
  -smp 4 ^
  -accel whpx ^
  -drive file=C:\ADAM_Sandbox\images\win10-gold.qcow2,format=qcow2 ^
  -vga std ^
  -display sdl ^
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:8443-:8443 ^
  -device e1000,netdev=net0 ^
  -chardev pipe,id=charmon0,path=adam_telemetry ^
  -device virtio-serial ^
  -device virtserialport,chardev=charmon0,name=adam_stealth_port

pause
