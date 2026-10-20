// RFC 3492 Punycode decoder, used to turn "xn--" hostname labels back into
// Unicode so homoglyph and mixed-script checks can see the real characters.
(function (root) {
  'use strict';
  const Verano = (root.Verano = root.Verano || {});

  const BASE = 36, T_MIN = 1, T_MAX = 26, SKEW = 38, DAMP = 700;
  const INITIAL_BIAS = 72, INITIAL_N = 128;

  function adapt(delta, numPoints, firstTime) {
    let k = 0;
    delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    for (; delta > ((BASE - T_MIN) * T_MAX) >> 1; k += BASE) {
      delta = Math.floor(delta / (BASE - T_MIN));
    }
    return Math.floor(k + ((BASE - T_MIN + 1) * delta) / (delta + SKEW));
  }

  function basicToDigit(cp) {
    if (cp >= 0x30 && cp < 0x3a) return cp - 22; // 0-9 -> 26-35
    if (cp >= 0x41 && cp < 0x5b) return cp - 0x41; // A-Z
    if (cp >= 0x61 && cp < 0x7b) return cp - 0x61; // a-z
    return BASE;
  }

  function decode(input) {
    const output = [];
    let i = 0, n = INITIAL_N, bias = INITIAL_BIAS;
    let basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) {
      if (input.charCodeAt(j) >= 0x80) throw new RangeError('punycode: non-basic code point');
      output.push(input.charCodeAt(j));
    }
    for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
      const oldi = i;
      for (let w = 1, k = BASE; ; k += BASE) {
        if (index >= input.length) throw new RangeError('punycode: truncated input');
        const digit = basicToDigit(input.charCodeAt(index++));
        if (digit >= BASE) throw new RangeError('punycode: bad digit');
        i += digit * w;
        const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
        if (digit < t) break;
        w *= BASE - t;
      }
      const out = output.length + 1;
      bias = adapt(i - oldi, out, oldi === 0);
      n += Math.floor(i / out);
      i %= out;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint.apply(null, output);
  }

  // Decode every xn-- label of a hostname. Labels that fail to decode are kept as-is.
  function hostToUnicode(host) {
    return host
      .split('.')
      .map((label) => {
        if (!/^xn--/i.test(label)) return label;
        try {
          return decode(label.slice(4).toLowerCase());
        } catch (e) {
          return label;
        }
      })
      .join('.');
  }

  Verano.punycode = { decode, hostToUnicode };
})(typeof globalThis !== 'undefined' ? globalThis : this);
