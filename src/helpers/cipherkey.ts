import { scrypt } from 'scrypt-js';
import jsSHA from 'jssha';
import { intArrToBigint } from './bigint';
import { debug } from 'debug';

const _debug = debug('cipherkey');

// Variáveis para hashing Scrypt.
const CPU_COST = 1 << 15; // 32768
const BLOCK_SIZE = 8;
const PARALLELIZATION_COST = 1;

const ALLOWED_CHARACTERS = '@#$%&*._!0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
const UPPERCASE_LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE_LETTERS = 'abcdefghijklmnopqrstuvwxyz';
const NUMBERS = '1234567890';
const VALID_SYMBOLS = '@#$%&*._!';

// Recebe uma string e retorna um array de bytes.
const encodeUtf8 = (str: string): Uint8Array => {
  return new TextEncoder().encode(str);
};

// Remove números ou símbolos do CipherKey.
export const sanitize = (cipherkey: string, no_symbols?: boolean, no_numbers?: boolean): string => {
  const _ = _debug.extend('sanitize');
  // Inicializa o SHAKE256 para o PRNG.
  /* DEBUG */ _('Inicializando SHAKE256');
  const prng_obj = new jsSHA('SHAKE256', 'TEXT', { encoding: 'UTF8' });

  // Converte o CipherKey para um Array de Strings.
  /* DEBUG */ _('Dividindo a senha por caracteres');
  const cipherkey_array = cipherkey.split('');

  // Gera um número aleatório de 0 ao tamanho do alfabeto - 1.
  const generateIndex = (hashThis: string): number => {
    prng_obj.update(hashThis);
    // Mesmo processo que generateIndex() em generateCipherKey().
    const prng = prng_obj.getHash('UINT8ARRAY', { outputLen: 256 });
    const result = intArrToBigint(prng);
    return Number(result % BigInt(ALPHABET.length));
  };

  // Se os símbolos precisam ser removidos.
  if (no_symbols) {
    /* DEBUG */ _('no_symbols é verdadeiro, removendo símbolos');
    for (let i = 0; i < cipherkey_array.length; i++) {
      // Se o caractere é um símbolo.
      if (VALID_SYMBOLS.includes(cipherkey_array[i])) {
        // Gera um índice aleatório usando (index + symbol) e substitui o símbolo por um caractere do alfabeto no índice gerado.
        cipherkey_array[i] = ALPHABET[generateIndex(i.toString() + cipherkey_array[i])];
      }
    }
  }

  // Se os números precisam ser removidos.
  if (no_numbers) {
    /* DEBUG */ _('no_numbers é verdadeiro, removendo números');
    for (let i = 0; i < cipherkey_array.length; i++) {
      // Se o caractere é um número.
      if (parseInt(cipherkey_array[i]) >= 0 && parseInt(cipherkey_array[i]) <= 9) {
        // Gera um índice aleatório usando (index + number) e substitui o número por um caractere do alfabeto no índice gerado.
        cipherkey_array[i] = ALPHABET[generateIndex(i.toString() + cipherkey_array[i])];
      }
    }
  }

  // Retorna o CipherKey como uma string.
  /* DEBUG */ _('Retornando o array de caracteres do CipherKey como uma string');
  return cipherkey_array.join('');
};

export const generateCipherKey = async (
  to_hash: string,
  cipherkey_length: number,
  website: string,
  username: string,
): Promise<string> => {
  const _ = _debug.extend('generateCipherKey');
  /* DEBUG */ _('Inicializando SHAKE256 e SHA3-512');
  // Inicializa o SHAKE256 para geração de números pseudoaleatórios.
  const sha_obj = new jsSHA('SHAKE256', 'UINT8ARRAY');
  // Inicializa o SHA3-512.
  const sha3_obj = new jsSHA('SHA3-512', 'TEXT', { encoding: 'UTF8' });

  // Converte o objeto JSON to_hash para seu próprio hash SHA3-512 em formato HEX.
  /* DEBUG */ _('Fazendo o hash de to_hash');
  sha3_obj.update(to_hash);
  to_hash = sha3_obj.getHash('HEX');

  // Gera Hash Scrypt.
  /* DEBUG */ _('Gerando o Hash Scrypt do to_hash já hasheado, concatenando e salgando website + username');
  const scrypt_hash = await scrypt(
    encodeUtf8(to_hash),
    encodeUtf8(website + username),
    CPU_COST,
    BLOCK_SIZE,
    PARALLELIZATION_COST,
    32,
  );
  /* DEBUG */ _('Hash Scrypt gerado');

  // Gera um número aleatório de 0 a modulo - 1.
  const generateIndex = (modulo: number) => {
    // Alimenta o scrypt_hash como seed para o SHAKE256.
    sha_obj.update(scrypt_hash);
    // PRNG é um array de 256 bits gerado pelo SHAKE256.
    const prng = sha_obj.getHash('UINT8ARRAY', { outputLen: 256 });
    // Converte o array de 256 bits em um BigInt de 256 bits.
    const result = intArrToBigint(prng);

    return Number(result % BigInt(modulo));
  };

  // Gera um índice aleatório de 0 a characterSet.length e retorna o caractere nesse índice.
  const pickCharacter = (char_set: string) => {
    return char_set[generateIndex(char_set.length)];
  };

  // Gera Array: 0,1,2,3,4,5,6...cipherkey_length - 1.
  let pick_index = [];

  // Verificar https://jsben.ch/3YHpR
  // O Chrome parece lidar com operações de array de forma significativamente mais rápida do que o Firefox, então usar Array.from() com um "iterável" personalizado é uma boa ideia em termos de desempenho, mesmo que seja negligente.
  if (globalThis?.navigator?.userAgent?.includes('Firefox')) {
    /* DEBUG */ _('Firefox detectado, usando Array.from com length e modificador de entrada');
    pick_index = Array.from({ length: cipherkey_length }, (_, i) => i);
  } else {
    /* DEBUG */ _('Não é o Firefox, usando o método "Set tmp[i] = i" dentro do loop for');
    for (let i = 0; i < cipherkey_length; i++) {
      // Definir o índice é muito mais rápido do que adicionar ao array, e como estamos operando em ordem, é relativamente seguro fazer isso.
      pick_index[i] = i;
    }
  }

  /* DEBUG */ _('Gerando a CipherKey a partir do alfabeto');
  // Gera um índice aleatório de 0 a pickIndex.length.
  let remove_index = generateIndex(pick_index.length);
  // index1 é o elemento no índice gerado e o valor está entre 0 e cipherkey_length - 1.
  const index1 = pick_index[remove_index];
  // Remove esse elemento do array pickIndex.
  // Nunca podemos escolher o mesmo elemento de pickIndex novamente e o tamanho de pickIndex diminui em 1.
  pick_index.splice(remove_index, 1);

  // Repete mais 3 vezes para index2, index3 e index4.
  remove_index = generateIndex(pick_index.length);
  const index2 = pick_index[remove_index];
  pick_index.splice(remove_index, 1);

  remove_index = generateIndex(pick_index.length);
  const index3 = pick_index[remove_index];
  pick_index.splice(remove_index, 1);

  remove_index = generateIndex(pick_index.length);
  const index4 = pick_index[remove_index];
  pick_index.splice(remove_index, 1);

  let cipherkey = '';
  // Constrói uma CipherKey de 0 a cipherkey_length - 1.
  for (let i = 0; i < cipherkey_length; i++) {
    if (i === index1) {
      // Se index1, escolha um caractere de letra minúscula.
      cipherkey += pickCharacter(LOWERCASE_LETTERS);
    } else if (i === index2) {
      // Se se index2, escolha um caractere de letra maiúscula.
      cipherkey += pickCharacter(UPPERCASE_LETTERS);
    } else if (i === index3) {
      // Se index3, escolha um caractere de símbolo válido.
      cipherkey += pickCharacter(VALID_SYMBOLS);
    } else if (i === index4) {
      // Se index4, escolha um caractere de número.
      cipherkey += pickCharacter(NUMBERS);
    } else {
      // Escolha um caractere de qualquer tipo se não for index1, index2, index3 ou index4.
      cipherkey += pickCharacter(ALLOWED_CHARACTERS);
    }
  }

  /* DEBUG */ _('Retornando a CipherKey');
  return cipherkey;
};