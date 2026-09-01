import subprocess
import os
import logging
from adam.common.errors import VMOperationError

logger = logging.getLogger("adam.sandbox.qemu.snapshot")

class QemuSnapshotManager:
    @staticmethod
    def create_overlay(qemu_img_path: str, base_image_path: str, overlay_path: str) -> None:
        """Create a qcow2 overlay file pointing to the base gold image."""
        if not os.path.exists(base_image_path):
            raise VMOperationError(f"Base VM image not found at {base_image_path}")

        overlay_dir = os.path.dirname(overlay_path)
        if overlay_dir:
            os.makedirs(overlay_dir, exist_ok=True)

        if os.path.exists(overlay_path):
            try:
                os.remove(overlay_path)
            except Exception as e:
                raise VMOperationError(f"Failed to clear old overlay file at {overlay_path}: {e}")

        cmd = [
            qemu_img_path, "create", "-f", "qcow2",
            "-b", base_image_path,
            "-F", "qcow2",
            overlay_path
        ]
        
        logger.info(f"Creating QEMU qcow2 overlay: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            logger.info(f"Overlay created successfully: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            raise VMOperationError(f"qemu-img overlay creation failed: {e.stderr.strip()}")
        except Exception as e:
            raise VMOperationError(f"Unexpected error creating overlay: {e}")

    @staticmethod
    def delete_overlay(overlay_path: str) -> None:
        """Remove the temporary overlay file to rollback all session changes."""
        if os.path.exists(overlay_path):
            logger.info(f"Deleting overlay file at {overlay_path} to roll back state...")
            try:
                os.remove(overlay_path)
            except Exception as e:
                logger.error(f"Failed to delete overlay file: {e}")
