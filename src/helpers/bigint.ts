export const intArrToBigint = (arr: Uint8Array): bigint => {
  let bits = 8n;

  if (ArrayBuffer.isView(arr)) {
    // Certifica se os bits têm o tamanho correto.
    bits = BigInt(arr.BYTES_PER_ELEMENT * 8);
  } else {
    // Caso contrário, transforma o array em um Uint8Array.
    arr = new Uint8Array(arr);
  }

  let buffered_result = 0n;

  for (const i of arr.values()) {
    const bint = BigInt(i);

    buffered_result = (buffered_result << bits) + bint;
  }

  return buffered_result;
};