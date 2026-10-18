// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract H4 {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address n) external {
        require(msg.sender == owner, 'no');
        owner = n;
    }
}
