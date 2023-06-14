"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = {
    arg1: '-oa',
    arg2: '--owner-address',
    options: {
        type: String,
        required: true,
        help: 'The cluster owner address'
    },
    interactive: {
        options: {
            type: 'text',
            message: 'Please provide a cluster owner address',
        }
    }
};
//# sourceMappingURL=owner-address.js.map