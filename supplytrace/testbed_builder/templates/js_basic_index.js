const lodash = require("lodash");

function normalizeNames(names) {
  return lodash.uniq(names.map((name) => name.trim()).filter(Boolean));
}

module.exports = { normalizeNames };

