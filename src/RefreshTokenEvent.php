<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use League\OAuth2\Server\RequestEvent;

class RefreshTokenEvent extends RequestEvent
{
    const REFRESH_TOKEN_REFRESHING = 'refresh_token.refreshing';

    /**
     * @var array
     */
    private $refreshToken;

    /**
     * RefreshTokenEvent constructor.
     *
     * @param string                 $name
     * @param ServerRequestInterface $request
     * @param array                  $refreshToken
     */
    public function __construct($name, ServerRequestInterface $request, array $refreshToken = [])
    {
        parent::__construct($name, $request);
        $this->refreshToken = $refreshToken;
    }

    /**
     * @return array
     * @codeCoverageIgnore
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }
}
