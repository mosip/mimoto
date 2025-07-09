package io.mosip.mimoto.dto;

public record WalletUnlockResult(WalletResponseDto responseDto, String decryptedWalletKey) {}
