const crypto = require('crypto');
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const bucket = process.env.S3_BUCKET;
const region = process.env.S3_REGION || 'ap-south-1';

function client() {
  if (!bucket) throw new Error('S3_BUCKET is not configured');
  return new S3Client({ region, endpoint: process.env.S3_ENDPOINT || undefined, forcePathStyle: process.env.S3_FORCE_PATH_STYLE === 'true' });
}

function createObjectKey({ authorId, originalName }) {
  const extension = originalName.toLowerCase().endsWith('.epub') ? 'epub' : 'pdf';
  return `books/${authorId}/${crypto.randomUUID()}.${extension}`;
}

async function uploadPrivateObject({ key, body, contentType }) {
  await client().send(new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    Body: body,
    ContentType: contentType,
    ServerSideEncryption: process.env.S3_SSE || undefined
  }));
  return key;
}

async function signedDownloadUrl(key, expiresIn = 300) {
  return getSignedUrl(client(), new GetObjectCommand({ Bucket: bucket, Key: key }), { expiresIn });
}

module.exports = { createObjectKey, uploadPrivateObject, signedDownloadUrl };
