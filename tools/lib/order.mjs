export function compareUnicodeCodeUnits(left, right) {
  const leftText = String(left);
  const rightText = String(right);
  const length = Math.min(leftText.length, rightText.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftText.charCodeAt(index) - rightText.charCodeAt(index);
    if (difference !== 0) return difference;
  }
  return leftText.length - rightText.length;
}

export function compareUtf8Bytes(left, right) {
  return Buffer.compare(Buffer.from(String(left), "utf8"), Buffer.from(String(right), "utf8"));
}
