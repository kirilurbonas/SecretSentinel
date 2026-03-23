import {
  IAMClient,
  CreateAccessKeyCommand,
  DeleteAccessKeyCommand,
  ListAccessKeysCommand,
} from "@aws-sdk/client-iam";

const client = new IAMClient({});

/**
 * AWS IAM rotation provider.
 * Creates a new access key for the IAM user embedded in the current value,
 * then deletes the old one. The returned value is JSON: { accessKeyId, secretAccessKey }.
 *
 * Expects currentValue to be JSON: { accessKeyId, userName }
 */
export async function rotate(
  _tenant: string,
  _env: string,
  _key: string,
  currentValue: string,
): Promise<string> {
  let parsed: { accessKeyId?: string; userName?: string };
  try {
    parsed = JSON.parse(currentValue) as { accessKeyId?: string; userName?: string };
  } catch {
    throw new Error("aws rotation: currentValue must be JSON with accessKeyId and userName");
  }

  const { accessKeyId: oldKeyId, userName } = parsed;
  if (!userName) throw new Error("aws rotation: userName missing in currentValue");

  // Create new key first so we don't lock out before the new one is ready.
  const created = await client.send(new CreateAccessKeyCommand({ UserName: userName }));
  const newKey = created.AccessKey;
  if (!newKey?.AccessKeyId || !newKey.SecretAccessKey) {
    throw new Error("aws rotation: CreateAccessKey did not return expected fields");
  }

  // Delete the old key if we know its ID.
  if (oldKeyId) {
    try {
      await client.send(
        new DeleteAccessKeyCommand({ UserName: userName, AccessKeyId: oldKeyId }),
      );
    } catch (err) {
      // Log but don't fail — the new key is already created.
      console.warn("aws rotation: failed to delete old access key", { oldKeyId, error: String(err) });
    }
  }

  return JSON.stringify({
    accessKeyId: newKey.AccessKeyId,
    secretAccessKey: newKey.SecretAccessKey,
    userName,
  });
}
