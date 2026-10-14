'use strict';

// The normalizer for each service, keyed by the events.service value.

const { normalizeFlask } = require('./flask');
const { normalizeCowrie } = require('./cowrie');
const { normalizeDionaea } = require('./dionaea');

module.exports = {
  'flask-http': normalizeFlask,
  cowrie: normalizeCowrie,
  dionaea: normalizeDionaea,
};
