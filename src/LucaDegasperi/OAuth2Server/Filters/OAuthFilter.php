<?php namespace LucaDegasperi\OAuth2Server\Filters;

use ResourceServer;
use Response;
use Config;

class OAuthFilter
{

    /**
     * Run the oauth filter
     *
     * @param Route $route the route being called
     * @param Request $request the request object
     * @param string $scope additional filter arguments
     * @return Response|null a bad response in case the request is invalid
     */
    public function filter()
    {
        try {
            ResourceServer::isValid(Config::get('lucadegasperi/oauth2-server-laravel::oauth2.http_headers_only'));
        } catch (\League\OAuth2\Server\Exception\InvalidAccessTokenException $e) {

            switch ($e->getMessage()) {
              case 'Access token is missing':
                return Response::json(array(
                    'status' => 9001,
                    'error' => 'missing access token',
                    'error_message' => $e->getMessage(),
                ), 403);
                break;
              case 'Access token is not valid':
                return Response::json(array(
                    'status' => 9002,
                    'error' => 'invalid access token',
                    'error_message' => $e->getMessage(),
                ), 403);
                break;
              default:
                return Response::json(array(
                    'status' => 9000,
                    'error' => 'access token required',
                    'error_message' => $e->getMessage(),
                ), 403);
                break;
            }

        }

        if (func_num_args() > 2) {
            $args = func_get_args();
            $scopes = array_slice($args, 2);

            foreach ($scopes as $s) {
                if (! ResourceServer::hasScope($s)) {
                    return Response::json(array(
                        'status' => 9002,
                        'error' => 'forbidden',
                        'error_message' => 'Only access token with scope '.$s.' can use this endpoint',
                    ), 403);
                }
            }
        }
    }
}
