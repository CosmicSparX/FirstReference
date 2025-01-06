/** @type {import('tailwindcss').Config} */

module.exports = {
      content: [
          "./templates/**/*.html",
          "./node_modules/flowbite/**/*.js",
      ],
      theme: {
        extend: {
            colors: {
                primary: '#FF9B9B',
                secondary: '#4B5563',
            },
            fontFamily: {
                Tinos: ["Tinos", "serif"],
            },
        },
      },
      plugins: [
        require('flowbite/plugin'),
      ]
}