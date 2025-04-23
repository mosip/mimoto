package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.util.WalletUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;


@Slf4j
@Service
public class WalletServiceImpl implements WalletService {

    @Autowired
    private WalletRepository walletRepository;

    @Autowired
    private WalletUtil walletHelper;
    @Override
    public String createWallet(String userId, String walletName, String pin)  {
        // Create a new wallet for the user
        return walletHelper.createWallet(userId, walletName, pin);
    }

    @Override
    public String getWalletKey(String userId, String walletId, String pin) {
        Optional<Wallet> existingWallet = walletRepository.findByUserIdAndId(userId, walletId);
        // Decrypt wallet key using the user's PIN
        return existingWallet.map(wallet -> walletHelper.decryptWalletKey(wallet.getWalletKey(), pin)).orElse(null);
    }

    @Override
    public List<WalletResponseDto> getWallets(String userId) {
        List<String> walletIds = walletRepository.findWalletIdByUserId(userId);
        return walletIds.stream()
                .map(WalletResponseDto::new)
                .collect(Collectors.toList());
    }
}
