// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/**
 * @dev BN256G2 operations
 */

interface BN256G2Interface{
  function ECTwistMul(uint256 s, uint256 pt1xx, uint256 pt1xy, uint256 pt1yx, uint256 pt1yy ) external view returns (uint256, uint256, uint256, uint256);
  function ECTwistAdd(uint256 pt1xx, uint256 pt1xy, uint256 pt1yx, uint256 pt1yy, uint256 pt2xx, uint256 pt2xy, uint256 pt2yx, uint256 pt2yy) external view returns (uint256, uint256, uint256, uint256);
}
