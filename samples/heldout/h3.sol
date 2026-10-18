// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract H3 {
    mapping(address => uint256) public bal;

    function put() external payable {
        bal[msg.sender] += msg.value;
    }

    function refund() external {
        uint256 a = bal[msg.sender];
        bal[msg.sender] = 0;
        payable(msg.sender).send(a);
    }
}
