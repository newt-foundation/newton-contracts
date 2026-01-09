// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @title VersionLib
/// @notice Library for parsing and comparing semantic versions (SemVer 2.0.0)
/// @dev Supports version format: MAJOR.MINOR.PATCH (e.g., "1.0.0")
library VersionLib {
    /// @notice Struct to represent a parsed semantic version
    struct Version {
        uint256 major;
        uint256 minor;
        uint256 patch;
    }

    error InvalidVersionFormat(string version);
    error InvalidVersionNumber(string component);

    /// @notice Parse a semantic version string into a Version struct
    /// @param versionStr The version string to parse (e.g., "1.0.0")
    /// @return version The parsed Version struct
    function parse(
        string memory versionStr
    ) internal pure returns (Version memory version) {
        bytes memory versionBytes = bytes(versionStr);
        require(versionBytes.length > 0, InvalidVersionFormat(versionStr));

        uint256 dotCount = 0;
        uint256 lastDotIndex = 0;
        uint256[3] memory components;
        uint256 componentIndex = 0;

        // Parse version components separated by dots
        for (uint256 i = 0; i < versionBytes.length; ++i) {
            if (versionBytes[i] == ".") {
                require(componentIndex < 2, InvalidVersionFormat(versionStr));
                components[componentIndex] = _parseNumber(versionBytes, lastDotIndex, i, versionStr);
                ++componentIndex;
                lastDotIndex = i + 1;
                ++dotCount;
            }
        }

        // Parse the last component (patch)
        require(dotCount == 2, InvalidVersionFormat(versionStr));
        components[componentIndex] =
            _parseNumber(versionBytes, lastDotIndex, versionBytes.length, versionStr);

        return Version({major: components[0], minor: components[1], patch: components[2]});
    }

    /// @notice Check if an actual version is compatible with a minimum required version
    /// @dev Compatible if: same major version AND (minor > min OR (minor == min AND patch >= min))
    /// @param actual The actual version string
    /// @param minimum The minimum required version string
    /// @return True if actual version is compatible with minimum version
    function isCompatible(
        string memory actual,
        string memory minimum
    ) internal pure returns (bool) {
        Version memory actualVer = parse(actual);
        Version memory minVer = parse(minimum);

        // Major version must match
        if (actualVer.major != minVer.major) {
            return false;
        }

        // Minor version must be greater or equal
        if (actualVer.minor > minVer.minor) {
            return true;
        }

        if (actualVer.minor < minVer.minor) {
            return false;
        }

        // If minor versions match, patch must be greater or equal
        return actualVer.patch >= minVer.patch;
    }

    /// @notice Parse a numeric component from a version string
    /// @param versionBytes The bytes of the version string
    /// @param startIndex The start index of the component
    /// @param endIndex The end index of the component (exclusive)
    /// @param versionStr The original version string (for error messages)
    /// @return The parsed number
    function _parseNumber(
        bytes memory versionBytes,
        uint256 startIndex,
        uint256 endIndex,
        string memory versionStr
    ) private pure returns (uint256) {
        require(endIndex > startIndex, InvalidVersionFormat(versionStr));

        uint256 result = 0;
        uint8 zeroChar = uint8(bytes1("0"));
        for (uint256 i = startIndex; i < endIndex; ++i) {
            bytes1 char = versionBytes[i];
            require(
                // "0" = 48, so > 47 is equivalent to >= 48. "9" = 57, so < 58 is equivalent to <= 57
                char > bytes1(uint8(47)) && char < bytes1(uint8(58)),
                InvalidVersionNumber(string(abi.encodePacked(char)))
            );
            result = result * 10 + uint256(uint8(char)) - uint256(zeroChar);
        }

        return result;
    }
}

