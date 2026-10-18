// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract H1 {
    mapping(address => uint256) public bal;

    function put() external payable {
        bal[msg.sender] += msg.value;
    }

    function take(uint256 a) external {
        require(bal[msg.sender] >= a, 'low');
        _pay(msg.sender, a);
        bal[msg.sender] -= a;
    }

    function _pay(address t, uint256 a) internal {
        (bool ok, ) = t.call{value: a}('');
        require(ok, 'fail');
    }
}
