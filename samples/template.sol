// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract Treasury {
    address public owner;
    mapping(address => uint256) public balances;
    bool private locked;

    modifier onlyOwner() { require(msg.sender == owner, 'not owner'); _; }
    modifier nonReentrant() { require(!locked, 'locked'); locked = true; _; locked = false; }

    constructor() { owner = msg.sender; }

    function deposit() external payable { balances[msg.sender] += msg.value; }

    function withdraw(uint256 amount) external /*@@NR_withdraw@@*/ {
        require(balances[msg.sender] >= amount, 'insufficient');
        /*@@PRE@@*/
        (bool ok, ) = msg.sender.call{value: amount}('');
        require(ok, 'send failed');
        /*@@POST@@*/
    }

    function refund(uint256 amount) external {
        require(balances[msg.sender] >= amount, 'insufficient');
        balances[msg.sender] -= amount;
        /*@@CALL_refund@@*/
    }

    function setOwner(address newOwner) external /*@@MOD_setOwner@@*/ { owner = newOwner; }

    function handOver(address who) external /*@@MOD_handOver@@*/ { _grant(who); }

    function _grant(address who) internal { owner = who; }
}
