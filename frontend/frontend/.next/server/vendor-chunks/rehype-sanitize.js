"use strict";
/*
 * ATTENTION: An "eval-source-map" devtool has been used.
 * This devtool is neither made for production nor for readable output files.
 * It uses "eval()" calls to create a separate source file with attached SourceMaps in the browser devtools.
 * If you are trying to read the output file, select a different devtool (https://webpack.js.org/configuration/devtool/)
 * or disable the default devtool with "devtool: false".
 * If you are looking for production-ready output files, see mode: "production" (https://webpack.js.org/configuration/mode/).
 */
exports.id = "vendor-chunks/rehype-sanitize";
exports.ids = ["vendor-chunks/rehype-sanitize"];
exports.modules = {

/***/ "(ssr)/./node_modules/rehype-sanitize/lib/index.js":
/*!***************************************************!*\
  !*** ./node_modules/rehype-sanitize/lib/index.js ***!
  \***************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

eval("__webpack_require__.r(__webpack_exports__);\n/* harmony export */ __webpack_require__.d(__webpack_exports__, {\n/* harmony export */   \"default\": () => (/* binding */ rehypeSanitize)\n/* harmony export */ });\n/* harmony import */ var hast_util_sanitize__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! hast-util-sanitize */ \"(ssr)/./node_modules/hast-util-sanitize/lib/index.js\");\n/**\n * @typedef {import('hast').Root} Root\n * @typedef {import('hast-util-sanitize').Schema} Schema\n */\n\n\n\n/**\n * Sanitize HTML.\n *\n * @param {Schema | null | undefined} [options]\n *   Configuration (optional).\n * @returns\n *   Transform.\n */\nfunction rehypeSanitize(options) {\n  /**\n   * @param {Root} tree\n   *   Tree.\n   * @returns {Root}\n   *   New tree.\n   */\n  return function (tree) {\n    // Assume root in -> root out.\n    const result = /** @type {Root} */ ((0,hast_util_sanitize__WEBPACK_IMPORTED_MODULE_0__.sanitize)(tree, options))\n    return result\n  }\n}\n//# sourceURL=[module]\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiKHNzcikvLi9ub2RlX21vZHVsZXMvcmVoeXBlLXNhbml0aXplL2xpYi9pbmRleC5qcyIsIm1hcHBpbmdzIjoiOzs7OztBQUFBO0FBQ0EsYUFBYSxxQkFBcUI7QUFDbEMsYUFBYSxxQ0FBcUM7QUFDbEQ7O0FBRTJDOztBQUUzQztBQUNBO0FBQ0E7QUFDQSxXQUFXLDJCQUEyQjtBQUN0QztBQUNBO0FBQ0E7QUFDQTtBQUNlO0FBQ2Y7QUFDQSxhQUFhLE1BQU07QUFDbkI7QUFDQSxlQUFlO0FBQ2Y7QUFDQTtBQUNBO0FBQ0E7QUFDQSw4QkFBOEIsTUFBTSxJQUFJLDREQUFRO0FBQ2hEO0FBQ0E7QUFDQSIsInNvdXJjZXMiOlsiQzpcXFVzZXJzXFxERUxMXFxEb3dubG9hZHNcXGN5YmVyX3RocmVhdF9yYWdfcmVmYWN0b3JlZFxcZnJvbnRlbmRcXGZyb250ZW5kXFxub2RlX21vZHVsZXNcXHJlaHlwZS1zYW5pdGl6ZVxcbGliXFxpbmRleC5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIEB0eXBlZGVmIHtpbXBvcnQoJ2hhc3QnKS5Sb290fSBSb290XG4gKiBAdHlwZWRlZiB7aW1wb3J0KCdoYXN0LXV0aWwtc2FuaXRpemUnKS5TY2hlbWF9IFNjaGVtYVxuICovXG5cbmltcG9ydCB7c2FuaXRpemV9IGZyb20gJ2hhc3QtdXRpbC1zYW5pdGl6ZSdcblxuLyoqXG4gKiBTYW5pdGl6ZSBIVE1MLlxuICpcbiAqIEBwYXJhbSB7U2NoZW1hIHwgbnVsbCB8IHVuZGVmaW5lZH0gW29wdGlvbnNdXG4gKiAgIENvbmZpZ3VyYXRpb24gKG9wdGlvbmFsKS5cbiAqIEByZXR1cm5zXG4gKiAgIFRyYW5zZm9ybS5cbiAqL1xuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gcmVoeXBlU2FuaXRpemUob3B0aW9ucykge1xuICAvKipcbiAgICogQHBhcmFtIHtSb290fSB0cmVlXG4gICAqICAgVHJlZS5cbiAgICogQHJldHVybnMge1Jvb3R9XG4gICAqICAgTmV3IHRyZWUuXG4gICAqL1xuICByZXR1cm4gZnVuY3Rpb24gKHRyZWUpIHtcbiAgICAvLyBBc3N1bWUgcm9vdCBpbiAtPiByb290IG91dC5cbiAgICBjb25zdCByZXN1bHQgPSAvKiogQHR5cGUge1Jvb3R9ICovIChzYW5pdGl6ZSh0cmVlLCBvcHRpb25zKSlcbiAgICByZXR1cm4gcmVzdWx0XG4gIH1cbn1cbiJdLCJuYW1lcyI6W10sImlnbm9yZUxpc3QiOlswXSwic291cmNlUm9vdCI6IiJ9\n//# sourceURL=webpack-internal:///(ssr)/./node_modules/rehype-sanitize/lib/index.js\n");

/***/ })

};
;