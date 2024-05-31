document.addEventListener('DOMContentLoaded', function() {
    // Initialize Stripe
    const stripe = Stripe('pk_test_51PMYKbP89MI6aokZCKBAnKGGXmRfLoTyUg27fTjijWiFt1TxAybr0ZNtHeTkvigqMLFecfshyvvkAKMNokpwWv7c00VqSrEGa2');
    const elements = stripe.elements();

    // Create card elements
    const style = {
        base: {
            color: '#32325d',
            fontFamily: '"Helvetica Neue", Helvetica, sans-serif',
            fontSmoothing: 'antialiased',
            fontSize: '16px',
            '::placeholder': {
                color: '#aab7c4'
            },
            padding: '10px',
            border: '1px solid #ccc',
            borderRadius: '4px',
            backgroundColor: '#f9f9f9',
        },
        invalid: {
            color: '#fa755a',
            iconColor: '#fa755a'
        }
    };

    const cardNumber = elements.create('cardNumber', { style });
    cardNumber.mount('#card-number');

    const cardExpiry = elements.create('cardExpiry', { style });
    cardExpiry.mount('#card-expiry');

    const cardCvc = elements.create('cardCvc', { style });
    cardCvc.mount('#card-cvc');

    // Retrieve subtotal from localStorage or other means
    const subtotal = localStorage.getItem('cartSubtotal') || '0.00';
    document.getElementById('subtotal').innerText = subtotal;

    // Handle form submission
    const form = document.getElementById('payment-form');
    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const cardholderName = document.getElementById('cardholder-name').value;

        const { token, error } = await stripe.createToken(cardNumber, {
            name: cardholderName
        });

        if (error) {
            // Inform the user if there was an error
            const errorElement = document.getElementById('card-errors');
            errorElement.textContent = error.message;
        } else {
            // Send the token to your server (or in this case, just log it)
            console.log('Token:', token);
            alert('Payment information submitted successfully!');
        }
    });
});
