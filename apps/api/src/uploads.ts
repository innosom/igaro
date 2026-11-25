// Shared image upload handling for logos and holder photos: one multipart file part named "file", type decided
// from the bytes, metadata stripped. Nothing from the client (content-type, file name) is used.
import type { FastifyRequest } from 'fastify';
import { AppError } from './errors.js';
import { sniffImage, stripMetadata, type ImageType } from './image.js';

export interface CleanImage {
  type: ImageType;
  /** Sanitised bytes: what is stored and what any hash must cover. */
  bytes: Buffer;
}

export async function readImageUpload(req: FastifyRequest, what: string): Promise<CleanImage> {
  if (!req.isMultipart()) throw new AppError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Expected multipart/form-data');
  let raw: Buffer;
  try {
    const part = await req.file();
    if (!part || part.fieldname !== 'file') {
      throw new AppError(400, 'BAD_REQUEST', 'Expected one file field named "file"');
    }
    raw = await part.toBuffer();
    if (part.file.truncated) throw new AppError(413, 'PAYLOAD_TOO_LARGE', `${what} is too large`);
  } catch (e) {
    if (e instanceof AppError) throw e;
    if ((e as { code?: string }).code === 'FST_REQ_FILE_TOO_LARGE') {
      throw new AppError(413, 'PAYLOAD_TOO_LARGE', `${what} is too large`);
    }
    throw new AppError(400, 'BAD_REQUEST', 'Invalid upload');
  }
  if (raw.length === 0) throw new AppError(400, 'BAD_REQUEST', 'Empty file');
  const type = sniffImage(raw);
  if (!type) throw new AppError(415, 'UNSUPPORTED_IMAGE_TYPE', `${what} must be a PNG or JPEG image`);
  const bytes = stripMetadata(raw, type);
  if (!bytes) throw new AppError(400, 'INVALID_IMAGE', 'The image file is damaged');
  return { type, bytes };
}
