# SecurityHub Documentation UI

A beautiful, modern, and interactive web-based documentation viewer for the SecurityHub vulnerability endpoints.

## Features

- 🎨 **Modern Design**: Clean, professional interface with smooth animations
- 🌓 **Dark Mode**: Toggle between light and dark themes
- 🔍 **Search**: Real-time search across all endpoints
- 📱 **Responsive**: Works perfectly on desktop, tablet, and mobile devices
- 🎯 **Interactive Navigation**: Easy-to-use sidebar with categorized endpoints
- 📊 **Status Indicators**: Visual status badges for each endpoint
- 🖨️ **Print Friendly**: Optimized for printing documentation

## Quick Start

1. **Open the documentation**:
   ```bash
   # Simply open index.html in your browser
   open index.html
   # Or use a local server
   python3 -m http.server 8000
   # Then visit http://localhost:8000
   ```

2. **Regenerate data** (if documentation changes):
   ```bash
   python3 parse_docs.py
   ```

## File Structure

```
docs-ui/
├── index.html          # Main HTML file
├── styles.css          # All styling and themes
├── app.js              # Application logic
├── data.js             # Auto-generated endpoint data
├── parse_docs.py       # Script to parse markdown and generate data.js
└── README.md           # This file
```

## Usage

### Navigation
- Use the sidebar to navigate through endpoint categories
- Click on any endpoint to view detailed documentation
- Use the search box to quickly find specific endpoints

### Viewing Endpoints
Each endpoint card displays:
- **HTTP Method & Path**: Color-coded method badges
- **Status Badge**: Functional status with icons
- **Description**: What the endpoint does
- **Implementation Details**: Step-by-step how it works
- **Dependencies**: All required models, services, and components
- **Issues**: Any known problems or limitations

### Dark Mode
Click the moon/sun icon in the header to toggle between light and dark themes. Your preference is saved in localStorage.

### Search
Type in the search box to filter endpoints by:
- Endpoint name
- API path
- Description content

## Customization

### Colors
Edit the CSS variables in `styles.css`:
```css
:root {
    --primary-color: #2563eb;
    --secondary-color: #10b981;
    /* ... */
}
```

### Adding Endpoints
1. Update the markdown documentation (`../vuln_endpoints_doc.md`)
2. Run `python3 parse_docs.py` to regenerate `data.js`
3. Refresh the browser

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers

## Requirements

- Modern web browser with JavaScript enabled
- Python 3.6+ (for parsing script)
- No server required (works as static files)

## License

Part of the SecurityHub project documentation.
