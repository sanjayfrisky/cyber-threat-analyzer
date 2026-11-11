"use strict";
/*
 * ATTENTION: An "eval-source-map" devtool has been used.
 * This devtool is neither made for production nor for readable output files.
 * It uses "eval()" calls to create a separate source file with attached SourceMaps in the browser devtools.
 * If you are trying to read the output file, select a different devtool (https://webpack.js.org/configuration/devtool/)
 * or disable the default devtool with "devtool: false".
 * If you are looking for production-ready output files, see mode: "production" (https://webpack.js.org/configuration/mode/).
 */
exports.id = "vendor-chunks/style-to-object";
exports.ids = ["vendor-chunks/style-to-object"];
exports.modules = {

/***/ "(ssr)/./node_modules/style-to-object/esm/index.mjs":
/*!****************************************************!*\
  !*** ./node_modules/style-to-object/esm/index.mjs ***!
  \****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

eval("__webpack_require__.r(__webpack_exports__);\n/* harmony export */ __webpack_require__.d(__webpack_exports__, {\n/* harmony export */   \"default\": () => (/* binding */ StyleToObject)\n/* harmony export */ });\n/* harmony import */ var inline_style_parser__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! inline-style-parser */ \"(ssr)/./node_modules/inline-style-parser/esm/index.mjs\");\n\n//#region src/index.ts\n/**\n* Parses inline style to object.\n*\n* @param style - Inline style.\n* @param iterator - Iterator.\n* @returns - Style object or null.\n*\n* @example Parsing inline style to object:\n*\n* ```js\n* import parse from 'style-to-object';\n* parse('line-height: 42;'); // { 'line-height': '42' }\n* ```\n*/\nfunction StyleToObject(style, iterator) {\n\tlet styleObject = null;\n\tif (!style || typeof style !== \"string\") return styleObject;\n\tconst declarations = (0,inline_style_parser__WEBPACK_IMPORTED_MODULE_0__[\"default\"])(style);\n\tconst hasIterator = typeof iterator === \"function\";\n\tdeclarations.forEach((declaration) => {\n\t\tif (declaration.type !== \"declaration\") return;\n\t\tconst { property, value } = declaration;\n\t\tif (hasIterator) iterator(property, value, declaration);\n\t\telse if (value) {\n\t\t\tstyleObject = styleObject ?? {};\n\t\t\tstyleObject[property] = value;\n\t\t}\n\t});\n\treturn styleObject;\n}\n//#endregion\n\n\n//# sourceMappingURL=index.mjs.map//# sourceURL=[module]\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiKHNzcikvLi9ub2RlX21vZHVsZXMvc3R5bGUtdG8tb2JqZWN0L2VzbS9pbmRleC5tanMiLCJtYXBwaW5ncyI6Ijs7Ozs7QUFBd0M7QUFDeEM7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EseUJBQXlCLElBQUksS0FBSztBQUNsQztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esc0JBQXNCLCtEQUFLO0FBQzNCO0FBQ0E7QUFDQTtBQUNBLFVBQVUsa0JBQWtCO0FBQzVCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxFQUFFO0FBQ0Y7QUFDQTtBQUNBO0FBQ29DOztBQUVwQyIsInNvdXJjZXMiOlsiQzpcXFVzZXJzXFxERUxMXFxEb3dubG9hZHNcXGN5YmVyX3RocmVhdF9yYWdfcmVmYWN0b3JlZFxcZnJvbnRlbmRcXGZyb250ZW5kXFxub2RlX21vZHVsZXNcXHN0eWxlLXRvLW9iamVjdFxcZXNtXFxpbmRleC5tanMiXSwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHBhcnNlIGZyb20gXCJpbmxpbmUtc3R5bGUtcGFyc2VyXCI7XG4vLyNyZWdpb24gc3JjL2luZGV4LnRzXG4vKipcbiogUGFyc2VzIGlubGluZSBzdHlsZSB0byBvYmplY3QuXG4qXG4qIEBwYXJhbSBzdHlsZSAtIElubGluZSBzdHlsZS5cbiogQHBhcmFtIGl0ZXJhdG9yIC0gSXRlcmF0b3IuXG4qIEByZXR1cm5zIC0gU3R5bGUgb2JqZWN0IG9yIG51bGwuXG4qXG4qIEBleGFtcGxlIFBhcnNpbmcgaW5saW5lIHN0eWxlIHRvIG9iamVjdDpcbipcbiogYGBganNcbiogaW1wb3J0IHBhcnNlIGZyb20gJ3N0eWxlLXRvLW9iamVjdCc7XG4qIHBhcnNlKCdsaW5lLWhlaWdodDogNDI7Jyk7IC8vIHsgJ2xpbmUtaGVpZ2h0JzogJzQyJyB9XG4qIGBgYFxuKi9cbmZ1bmN0aW9uIFN0eWxlVG9PYmplY3Qoc3R5bGUsIGl0ZXJhdG9yKSB7XG5cdGxldCBzdHlsZU9iamVjdCA9IG51bGw7XG5cdGlmICghc3R5bGUgfHwgdHlwZW9mIHN0eWxlICE9PSBcInN0cmluZ1wiKSByZXR1cm4gc3R5bGVPYmplY3Q7XG5cdGNvbnN0IGRlY2xhcmF0aW9ucyA9IHBhcnNlKHN0eWxlKTtcblx0Y29uc3QgaGFzSXRlcmF0b3IgPSB0eXBlb2YgaXRlcmF0b3IgPT09IFwiZnVuY3Rpb25cIjtcblx0ZGVjbGFyYXRpb25zLmZvckVhY2goKGRlY2xhcmF0aW9uKSA9PiB7XG5cdFx0aWYgKGRlY2xhcmF0aW9uLnR5cGUgIT09IFwiZGVjbGFyYXRpb25cIikgcmV0dXJuO1xuXHRcdGNvbnN0IHsgcHJvcGVydHksIHZhbHVlIH0gPSBkZWNsYXJhdGlvbjtcblx0XHRpZiAoaGFzSXRlcmF0b3IpIGl0ZXJhdG9yKHByb3BlcnR5LCB2YWx1ZSwgZGVjbGFyYXRpb24pO1xuXHRcdGVsc2UgaWYgKHZhbHVlKSB7XG5cdFx0XHRzdHlsZU9iamVjdCA9IHN0eWxlT2JqZWN0ID8/IHt9O1xuXHRcdFx0c3R5bGVPYmplY3RbcHJvcGVydHldID0gdmFsdWU7XG5cdFx0fVxuXHR9KTtcblx0cmV0dXJuIHN0eWxlT2JqZWN0O1xufVxuLy8jZW5kcmVnaW9uXG5leHBvcnQgeyBTdHlsZVRvT2JqZWN0IGFzIGRlZmF1bHQgfTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9aW5kZXgubWpzLm1hcCJdLCJuYW1lcyI6W10sImlnbm9yZUxpc3QiOlswXSwic291cmNlUm9vdCI6IiJ9\n//# sourceURL=webpack-internal:///(ssr)/./node_modules/style-to-object/esm/index.mjs\n");

/***/ })

};
;