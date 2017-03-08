<?php

namespace RonMelkhior\CoinpaymentsIPN;

use RonMelkhior\CoinpaymentsIPN\Initialize;
use RonMelkhior\CoinpaymentsIPN\Exceptions\InvalidRequestException;
use RonMelkhior\CoinpaymentsIPN\Exceptions\InsufficientDataException;
use RonMelkhior\CoinpaymentsIPN\Exceptions\FailedPaymentException;

class IPN
{
    use Initialize;

    /**
     * Validate the IPN request and payment.
     *
     * @param  array  $post_data
     * @param  array  $server_data
     * @return mixed
     */
    public function validate(array $post_data, array $server_data)
    {
        if (!isset($post_data['ipn_mode'], $post_data['merchant'], $post_data['status'], $post_data['status_text'])) {
            throw new InvalidRequestException("Insufficient POST data provided.");
        }

        if ($post_data['ipn_mode'] == 'httpauth') {
            if ($server_data['PHP_AUTH_USER'] !== $this->merchant_id) {
                throw new InsufficientDataException("Invalid merchant ID provided.");
            }

            if ($server_data['PHP_AUTH_PW'] !== $this->ipn_secret) {
                throw new InsufficientDataException("Invalid IPN secret provided.");
            }
        } elseif ($post_data['ipn_mode'] == 'hmac') {
            $hmac = hash_hmac("sha512", file_get_contents('php://input'), $this->ipn_secret);

            if ($hmac !== $server_data['HTTP_HMAC']) {
                throw new InsufficientDataException("Invalid HMAC provided.");
            }

            if ($post_data['merchant'] !== $this->merchant_id) {
                throw new InsufficientDataException("Invalid merchant ID provided.");
            }
        } else {
            throw new InvalidRequestException("Invalid IPN mode provided.");
        }


        $order_status = $post_data['status'];
        $order_status_text = $post_data['status_text'];

        if ($order_status >= 100 || $order_status == 2) {
            // payment is complete or queued for nightly payout, success 
            return true;
        } else if ($order_status < 0) {
            //payment error, this is usually final but payments will sometimes be reopened if there was no exchange rate
            // conversion or with seller consent 
            throw new FailedPaymentException("{$order_status}: {$order_status_text}");
        } else {
            //payment is pending, you can optionally add a note to the order page
            return false;
        }
    }
}
