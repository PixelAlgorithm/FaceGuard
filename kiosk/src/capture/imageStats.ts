/** Cheap per-frame image statistics on a small face crop (advisory; the edge recomputes on JPEGs). */

export interface CropStats {
  luma: number // mean Y (0-255) on the central face region
  overexposed: number // fraction of central pixels with Y >= 250
  blurVar: number // Laplacian variance on the grey crop
  rgb: [number, number, number] | null // mean skin-patch colour (chroma sample)
}

/**
 * @param img     RGBA crop (e.g. 112x112) of the face bounding square
 * @param patches skin patch centres in crop pixel coordinates
 * @param half    patch half-size in crop pixels
 */
export function analyseCrop(img: ImageData, patches: Array<[number, number]>, half: number): CropStats {
  const { data, width: w, height: h } = img
  const grey = new Float32Array(w * h)
  const x0 = Math.floor(w * 0.18)
  const x1 = Math.ceil(w * 0.82)
  const y0 = Math.floor(h * 0.15)
  const y1 = Math.ceil(h * 0.85)
  let lumaSum = 0
  let lumaN = 0
  let over = 0
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const i = (y * w + x) * 4
      const Y = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]
      grey[y * w + x] = Y
      if (x >= x0 && x < x1 && y >= y0 && y < y1) {
        lumaSum += Y
        lumaN++
        if (Y >= 250) over++
      }
    }
  }
  let s = 0
  let s2 = 0
  let n = 0
  for (let y = 1; y < h - 1; y++) {
    for (let x = 1; x < w - 1; x++) {
      const k = y * w + x
      const lap = grey[k - w] + grey[k + w] + grey[k - 1] + grey[k + 1] - 4 * grey[k]
      s += lap
      s2 += lap * lap
      n++
    }
  }
  const mean = n ? s / n : 0
  const blurVar = n ? s2 / n - mean * mean : 0

  let r = 0
  let g = 0
  let b = 0
  let m = 0
  for (const [cx, cy] of patches) {
    const px0 = Math.max(0, Math.round(cx - half))
    const px1 = Math.min(w, Math.round(cx + half))
    const py0 = Math.max(0, Math.round(cy - half))
    const py1 = Math.min(h, Math.round(cy + half))
    for (let y = py0; y < py1; y++) {
      for (let x = px0; x < px1; x++) {
        const i = (y * w + x) * 4
        if (data[i + 3] === 0) continue // outside the source frame
        r += data[i]
        g += data[i + 1]
        b += data[i + 2]
        m++
      }
    }
  }
  return {
    luma: lumaN ? lumaSum / lumaN : 0,
    overexposed: lumaN ? over / lumaN : 0,
    blurVar,
    rgb: m ? [r / m, g / m, b / m] : null,
  }
}

export function canvasToJpeg(canvas: HTMLCanvasElement, quality: number): Promise<Blob> {
  return new Promise((resolve, reject) => {
    canvas.toBlob(
      (blob) => (blob ? resolve(blob) : reject(new Error('JPEG encoding failed'))),
      'image/jpeg',
      quality,
    )
  })
}
