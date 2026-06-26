# API Reference Frontend

A simple, interactive frontend to visualize the SecurityHub API reference documentation.

## Features

- 📋 **Complete API Reference** - All endpoints organized by sections
- 🔍 **Search & Filter** - Search by path, description, methods, or capabilities
- 📊 **Statistics** - View total endpoints, sections, and filtered results
- 🎨 **Modern UI** - Clean, responsive design
- 🔄 **Collapsible Sections** - Expand/collapse sections for better navigation
- 🏷️ **Method Badges** - Color-coded HTTP method indicators
- 🔐 **Auth Indicators** - Clear authentication requirements
- 💼 **Capability Tags** - Visual RBAC capability requirements

## Usage

### Option 1: Open Directly (Recommended)

Simply open `index.html` in a web browser. The JSON data is embedded in `api-data.js`, so it works without a server!

**Note**: The `api-data.js` file is auto-generated from `../api-reference.json`. If you update the JSON file, regenerate it:
```bash
cd documentation
python3 -c "import json; data = json.load(open('api-reference.json')); open('frontend/api-data.js', 'w').write('window.API_REFERENCE_DATA = ' + json.dumps(data, indent=2) + ';')"
```

### Option 2: Serve Locally

For best results, serve via a local web server:

```bash
# Using Python 3
cd documentation/frontend
python3 -m http.server 8000

# Then open http://localhost:8000 in your browser
```

```bash
# Using Node.js (if you have http-server installed)
npx http-server -p 8000
```

### Option 3: Integrate with Backend

You can serve this from your Django application by adding it to your static files or creating a view.

## File Structure

```
frontend/
├── index.html      # Main HTML file
├── styles.css      # Styling
├── app.js          # JavaScript logic
└── README.md       # This file
```

## Features Explained

### Search Bar
- **Search Input**: Searches across paths, descriptions, methods, and capabilities
- **Section Filter**: Filter by specific API section (Authentication, Projects, etc.)
- **Method Filter**: Filter by HTTP method (GET, POST, PATCH, DELETE)
- **Clear Filters**: Reset all filters

### Endpoint Cards
Each endpoint card displays:
- HTTP method badges (color-coded)
- Full API path
- Authentication requirement
- Description
- Path parameters (if any)
- Query parameters (if any)
- Request body structure (if any)
- Response structure (if any)
- Required capabilities (RBAC)

### Statistics
- **Total Endpoints**: All endpoints in the API
- **Sections**: Number of API sections
- **Visible**: Currently visible endpoints after filtering

## Customization

### Colors
Edit the CSS variables in `styles.css`:

```css
:root {
    --primary-color: #2563eb;
    --secondary-color: #1e40af;
    --success-color: #10b981;
    --danger-color: #ef4444;
    --warning-color: #f59e0b;
    /* ... */
}
```

### Layout
Modify the grid and flexbox layouts in `styles.css` to adjust spacing and arrangement.

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers

## Notes

- The frontend expects `api-reference.json` to be in the parent directory
- All data is loaded client-side (no backend required)
- Search and filtering happen in real-time
- Sections are collapsed by default for better performance
