// Brands that phishing kits impersonate most often.
//   domains   registrable domains the brand really owns (always trusted)
//   tokens    strings checked against hostnames for lookalikes / brand-in-domain
//   keywords  phrases checked against page text for impersonation
//   ignore    real, unrelated labels that would otherwise look like a typo of a token
(function (root) {
  'use strict';
  const Verano = (root.Verano = root.Verano || {});

  const BRANDS = [
    { name: 'PayPal', domains: ['paypal.com', 'paypal.me', 'paypalobjects.com', 'paypal-community.com'], tokens: ['paypal'], keywords: ['paypal'], ignore: ['paypay'] },
    { name: 'Apple', domains: ['apple.com', 'icloud.com', 'me.com', 'mzstatic.com', 'apple.news'], tokens: ['apple', 'icloud', 'appleid'], keywords: ['apple id', 'icloud', 'apple account'] },
    {
      name: 'Microsoft',
      domains: ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'office365.com', 'outlook.com', 'sharepoint.com', 'onedrive.com', 'msn.com', 'bing.com', 'azure.com', 'xbox.com', 'skype.com', 'msauth.net', 'msftauth.net', 'windows.net', 'hotmail.com', 'microsoft365.com', 'cloud.microsoft'],
      tokens: ['microsoft', 'office365', 'microsoftonline', 'outlook', 'onedrive', 'sharepoint', 'hotmail'],
      keywords: ['microsoft', 'office 365', 'microsoft 365', 'outlook', 'onedrive', 'sharepoint', 'hotmail'],
    },
    {
      name: 'Google',
      domains: ['google.com', 'gmail.com', 'youtube.com', 'googleusercontent.com', 'gstatic.com', 'google.co.uk', 'google.de', 'google.fr', 'google.es', 'google.it', 'google.ca', 'google.com.au', 'google.co.jp', 'google.com.mx', 'google.com.br', 'google.co.in', 'withgoogle.com'],
      tokens: ['google', 'gmail'],
      keywords: ['google account', 'gmail', 'sign in with google'],
    },
    {
      name: 'Amazon',
      domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.es', 'amazon.it', 'amazon.ca', 'amazon.com.au', 'amazon.co.jp', 'amazon.com.mx', 'amazon.com.br', 'amazon.in', 'amazonaws.com', 'media-amazon.com', 'ssl-images-amazon.com', 'primevideo.com'],
      tokens: ['amazon'],
      keywords: ['amazon', 'prime membership'],
    },
    { name: 'Netflix', domains: ['netflix.com', 'nflxext.com', 'nflximg.net'], tokens: ['netflix'], keywords: ['netflix'] },
    { name: 'Facebook', domains: ['facebook.com', 'fb.com', 'messenger.com', 'meta.com', 'fbcdn.net'], tokens: ['facebook'], keywords: ['facebook', 'meta business'] },
    { name: 'Instagram', domains: ['instagram.com', 'cdninstagram.com'], tokens: ['instagram'], keywords: ['instagram'] },
    { name: 'WhatsApp', domains: ['whatsapp.com', 'whatsapp.net'], tokens: ['whatsapp'], keywords: ['whatsapp'] },
    { name: 'LinkedIn', domains: ['linkedin.com', 'licdn.com'], tokens: ['linkedin'], keywords: ['linkedin'] },
    { name: 'X (Twitter)', domains: ['twitter.com', 'x.com', 'twimg.com'], tokens: ['twitter'], keywords: ['twitter'] },
    { name: 'Dropbox', domains: ['dropbox.com', 'dropboxusercontent.com'], tokens: ['dropbox'], keywords: ['dropbox'] },
    { name: 'DocuSign', domains: ['docusign.com', 'docusign.net'], tokens: ['docusign'], keywords: ['docusign'] },
    { name: 'Adobe', domains: ['adobe.com', 'adobelogin.com', 'typekit.net'], tokens: ['adobe'], keywords: ['adobe document cloud', 'adobe acrobat', 'adobe sign'] },
    { name: 'Chase', domains: ['chase.com', 'jpmorganchase.com'], tokens: ['chase'], keywords: ['chase bank', 'chase online'] },
    { name: 'Bank of America', domains: ['bankofamerica.com', 'bofa.com'], tokens: ['bankofamerica'], keywords: ['bank of america'] },
    { name: 'Wells Fargo', domains: ['wellsfargo.com', 'wf.com'], tokens: ['wellsfargo'], keywords: ['wells fargo'] },
    { name: 'Citibank', domains: ['citi.com', 'citibank.com', 'citigroup.com'], tokens: ['citibank'], keywords: ['citibank', 'citi online'] },
    { name: 'USPS', domains: ['usps.com'], tokens: ['usps'], keywords: ['usps', 'postal service'] },
    { name: 'UPS', domains: ['ups.com'], tokens: ['ups'], keywords: ['ups my choice'] },
    { name: 'DHL', domains: ['dhl.com', 'dhl.de'], tokens: ['dhl'], keywords: ['dhl express', 'dhl parcel'] },
    { name: 'FedEx', domains: ['fedex.com'], tokens: ['fedex'], keywords: ['fedex'] },
    { name: 'Coinbase', domains: ['coinbase.com'], tokens: ['coinbase'], keywords: ['coinbase'] },
    { name: 'Binance', domains: ['binance.com', 'binance.us'], tokens: ['binance'], keywords: ['binance'], ignore: ['finance'] },
    { name: 'MetaMask', domains: ['metamask.io'], tokens: ['metamask'], keywords: ['metamask'] },
    { name: 'Steam', domains: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com'], tokens: ['steampowered', 'steamcommunity'], keywords: ['steam community', 'steam guard'] },
    { name: 'Yahoo', domains: ['yahoo.com', 'yimg.com', 'yahoo.co.jp'], tokens: ['yahoo'], keywords: ['yahoo mail', 'yahoo account'] },
    { name: 'Spotify', domains: ['spotify.com', 'scdn.co'], tokens: ['spotify'], keywords: ['spotify'] },
    { name: 'eBay', domains: ['ebay.com', 'ebay.co.uk', 'ebay.de', 'ebayimg.com'], tokens: ['ebay'], keywords: ['ebay'] },
    { name: 'Discord', domains: ['discord.com', 'discord.gg', 'discordapp.com', 'discord.media'], tokens: ['discord'], keywords: ['discord nitro', 'discord'] },
    { name: 'GitHub', domains: ['github.com', 'githubassets.com', 'githubusercontent.com'], tokens: ['github'], keywords: ['sign in to github'] },
    { name: 'Okta', domains: ['okta.com', 'oktacdn.com', 'okta-emea.com'], tokens: ['okta'], keywords: ['okta verify'] },
    { name: 'IRS', domains: ['irs.gov'], tokens: ['irs'], keywords: ['internal revenue service', 'irs refund'] },
    { name: 'Telegram', domains: ['telegram.org', 't.me'], tokens: ['telegram'], keywords: ['telegram'] },
    { name: 'Roblox', domains: ['roblox.com', 'rbxcdn.com'], tokens: ['roblox'], keywords: ['roblox'] },
  ];

  const domainToBrand = new Map();
  for (const brand of BRANDS) for (const d of brand.domains) domainToBrand.set(d, brand);

  // The brand that owns this host, if any (checks every parent domain, e.g. a.b.paypal.com).
  function brandOwning(host) {
    const labels = host.split('.');
    for (let i = 0; i < labels.length - 1; i++) {
      const brand = domainToBrand.get(labels.slice(i).join('.'));
      if (brand) return brand;
    }
    return null;
  }

  Verano.brands = { BRANDS, brandOwning };
})(typeof globalThis !== 'undefined' ? globalThis : this);
