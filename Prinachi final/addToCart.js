const cartUtils = {
    addToCart: function(productId) {
        let cart = JSON.parse(localStorage.getItem('cart')) || [];
        let productInfo = document.getElementById(productId);
        let productTitle = productInfo.querySelector('.productTitle').innerText;
        let productPrice = parseFloat(productInfo.querySelector('.productPrice').innerText.replace('$', ''));
        let productPicture = productInfo.querySelector('.productPicture').src;

        let product = cart.find(p => p.productTitle === productTitle);
        if (product) {
            product.quantity += 1;
        } else {
            cart.push({ productTitle, productPrice, productPicture, quantity: 1 });
        }
        localStorage.setItem('cart', JSON.stringify(cart));
    },

    displayCart: function() {
        let cart = JSON.parse(localStorage.getItem('cart')) || [];
        let totalSum = 0;

        let content = cart.map(item => `
            <div class="cart-item">
                <div class="product">
                    <img src="${item.productPicture}" alt="Product Image">
                    <div class="item-details">
                        <p class="product-name">${item.productTitle}</p>
                        <p class="product-price">$${item.productPrice.toFixed(2)}</p>
                    </div>
                </div>
                <div class="item-quantity">
                    <button class="quantity-btn" onclick="cartUtils.changeQuantity('${item.productTitle}', -1)">-</button>
                    <input type="text" value="${item.quantity}" class="quantity-input" readonly>
                    <button class="quantity-btn" onclick="cartUtils.changeQuantity('${item.productTitle}', 1)">+</button>
                    <button class="remove-btn" onclick="cartUtils.removeFromCart('${item.productTitle}')">🗑</button>
                </div>
                <p class="item-total">$${(item.productPrice * item.quantity).toFixed(2)}</p>
            </div>
        `).join('');

        if (cart.length === 0) {
            content = '<h1>Your cart is empty :/</h1>';
        } else {
            totalSum = cart.reduce((sum, item) => sum + (item.productPrice * item.quantity), 0);
        }

        document.getElementById('cartItems').innerHTML = content;
        document.querySelector('.subtotal').textContent = `Subtotal $${totalSum.toFixed(2)}`;
    },

    changeQuantity: function(productTitle, change) {
        let cart = JSON.parse(localStorage.getItem('cart')) || [];
        let product = cart.find(item => item.productTitle === productTitle);

        if (product) {
            product.quantity += change;
            if (product.quantity <= 0) {
                cart = cart.filter(item => item.productTitle !== productTitle);
            }
            localStorage.setItem('cart', JSON.stringify(cart));
            this.displayCart();
        }
    },

    removeFromCart: function(productTitle) {
        let cart = JSON.parse(localStorage.getItem('cart')) || [];
        cart = cart.filter(item => item.productTitle !== productTitle);
        localStorage.setItem('cart', JSON.stringify(cart));
        this.displayCart();
    },

    getCartTotal: function() {
        let cart = JSON.parse(localStorage.getItem('cart')) || [];
        return cart.reduce((sum, item) => sum + (item.productPrice * item.quantity), 0).toFixed(2);
    }
};

window.onload = function() {
    cartUtils.displayCart();

    document.querySelector('.checkout-btn').addEventListener('click', function() {
        window.location.href = 'payment.html';
    });
};