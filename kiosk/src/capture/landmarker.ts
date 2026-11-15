/** MediaPipe Face Landmarker (VIDEO mode). WASM + .task model are served locally from public/ (offline). */
import { FaceLandmarker, FilesetResolver } from '@mediapipe/tasks-vision'
import { DELEGATE_OVERRIDE } from '../config'

const base = import.meta.env.BASE_URL.replace(/\/?$/, '/')
export const WASM_PATH = `${base}mediapipe/wasm`
export const MODEL_PATH = `${base}models/face_landmarker.task`

export async function createFaceLandmarker(): Promise<{ landmarker: FaceLandmarker; delegate: 'GPU' | 'CPU' }> {
  const fileset = await FilesetResolver.forVisionTasks(WASM_PATH)
  const make = (delegate: 'GPU' | 'CPU') =>
    FaceLandmarker.createFromOptions(fileset, {
      baseOptions: { modelAssetPath: MODEL_PATH, delegate },
      runningMode: 'VIDEO',
      numFaces: 2, // 2 so "one person at a time" can be detected
      minFaceDetectionConfidence: 0.5,
      minFacePresenceConfidence: 0.5,
      minTrackingConfidence: 0.5,
      outputFaceBlendshapes: true,
      outputFacialTransformationMatrixes: true,
    })
  if (DELEGATE_OVERRIDE === 'CPU') return { landmarker: await make('CPU'), delegate: 'CPU' }
  try {
    return { landmarker: await make('GPU'), delegate: 'GPU' }
  } catch (gpuErr) {
    console.warn('[landmarker] GPU delegate failed, falling back to CPU', gpuErr)
    return { landmarker: await make('CPU'), delegate: 'CPU' }
  }
}
