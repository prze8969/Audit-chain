// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract H2 {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function transferOwnership(address n) external {
        admin = n;
    }
}
