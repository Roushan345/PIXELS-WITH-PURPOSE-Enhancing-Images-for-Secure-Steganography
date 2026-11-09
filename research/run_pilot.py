
import csv
import time
from pathlib import Path

import numpy as np
from PIL import Image
from skimage.metrics import structural_similarity

from algorithms.common_crypto import create_packet
from algorithms.lsb_algorithms import embed_image, extract_image


BASE = Path(__file__).resolve().parent

COVERS = BASE / "datasets" / "covers"
PAYLOADS = BASE / "payloads"
RESULTS = BASE / "results"

PASSWORD = "PWP_Research_Test_2026"
METHODS = ["sequential", "prng"]


def calculate_metrics(original_path, stego_path):
    """Calculate MSE, PSNR and standard SSIM."""

    original = np.array(
        Image.open(original_path).convert("RGB"),
        dtype=np.float64
    )

    stego = np.array(
        Image.open(stego_path).convert("RGB"),
        dtype=np.float64
    )

    mse = float(np.mean((original - stego) ** 2))

    if mse == 0:
        psnr = float("inf")
    else:
        psnr = float(10 * np.log10((255 ** 2) / mse))

    ssim = float(
        structural_similarity(
            original,
            stego,
            channel_axis=-1,
            data_range=255
        )
    )

    return mse, psnr, ssim


def main():

    RESULTS.mkdir(parents=True, exist_ok=True)

    secret_file = PAYLOADS / "secret.txt"

    if not secret_file.exists():
        print("ERROR: Create research/payloads/secret.txt first.")
        return

    if not COVERS.exists():
        print("ERROR: Create research/datasets/covers/ and add images.")
        return

    message = secret_file.read_bytes()

    if not message:
        print("ERROR: Your secret.txt file is empty.")
        return

    cover_images = sorted(
        path for path in COVERS.iterdir()
        if path.suffix.lower() in [".png", ".jpg", ".jpeg"]
    )

    if not cover_images:
        print("ERROR: No cover images found.")
        return

    output_rows = []

    print("\nPIXELS WITH PURPOSE - PILOT EXPERIMENT")
    print("=" * 55)

    for cover in cover_images:

        print(f"\nTesting image: {cover.name}")

        # Create ONE encrypted packet for both algorithms.
        packet = create_packet(message, PASSWORD)

        for method in METHODS:

            output_path = RESULTS / f"{cover.stem}_{method}.png"

            try:
                # Embedding
                start = time.perf_counter()

                embed_info = embed_image(
                    str(cover),
                    str(output_path),
                    message,
                    PASSWORD,
                    method,
                    packet=packet
                )

                embedding_time = (
                    time.perf_counter() - start
                ) * 1000

                # Extraction
                start = time.perf_counter()

                recovered = extract_image(
                    str(output_path),
                    PASSWORD,
                    method
                )

                extraction_time = (
                    time.perf_counter() - start
                ) * 1000

                success = recovered == message

                # Image quality
                mse, psnr, ssim = calculate_metrics(
                    cover,
                    output_path
                )

                row = {
                    "image": cover.name,
                    "algorithm": method,
                    "original_payload_bytes": len(message),
                    "encrypted_payload_bytes": embed_info["payload_bytes"],
                    "mse": mse,
                    "psnr_db": psnr,
                    "ssim": ssim,
                    "embedding_time_ms": embedding_time,
                    "extraction_time_ms": extraction_time,
                    "extraction_success": success
                }

                output_rows.append(row)

                print(f"  Algorithm: {method}")
                print(f"  PSNR: {psnr:.4f} dB")
                print(f"  SSIM: {ssim:.6f}")
                print(f"  MSE: {mse:.6f}")
                print(f"  Extraction: {success}")

            except Exception as error:
                print(f"  ERROR ({method}): {error}")

    if not output_rows:
        print("\nNo results generated.")
        return

    csv_path = RESULTS / "pilot_results.csv"

    with open(
        csv_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=output_rows[0].keys()
        )

        writer.writeheader()
        writer.writerows(output_rows)

    print("\n" + "=" * 55)
    print("PILOT EXPERIMENT COMPLETED")
    print(f"Total tests: {len(output_rows)}")
    print(f"Successful extractions: {sum(r['extraction_success'] for r in output_rows)}")
    print(f"Results saved to: {csv_path}")


if __name__ == "__main__":
    main()
