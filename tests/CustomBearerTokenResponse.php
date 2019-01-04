<?php

namespace LeagueTests;

use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;

class CustomBearerTokenResponse extends BearerTokenResponse {
    /* @return null|CryptKey */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    public function getEncryptionKey()
    {
        return $this->encryptionKey;
    }
}
