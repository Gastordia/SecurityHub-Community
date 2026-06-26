/**
 * Tests for ScannerIntegration component
 */
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ThemeProvider } from '@material-tailwind/react';
import ScannerIntegration from '../src/components/scanner-integration';
import { getSupportedScanners, uploadParserFile } from '../src/lib/data/api';

// Mock the API functions
jest.mock('../src/lib/data/api', () => ({
  getSupportedScanners: jest.fn(),
  uploadParserFile: jest.fn(),
}));

// Mock the toast notifications
jest.mock('react-hot-toast', () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn(),
  },
}));

// Mock the ThemeContext
const mockThemeContext = {
  theme: 'light',
  toggleTheme: jest.fn(),
};

jest.mock('../src/layouts/layout', () => ({
  ThemeContext: {
    Provider: ({ children, value }: any) => children,
  },
  useTheme: () => mockThemeContext,
}));

const mockScanners = [
  {
    name: 'Nessus',
    version: '10.0',
    formats: ['XML', 'CSV'],
    author: 'Tenable',
    website: 'https://www.tenable.com',
    capabilities: ['Network scanning', 'Vulnerability assessment'],
    description: 'Professional vulnerability scanner',
  },
  {
    name: 'OpenVAS',
    version: '21.4',
    formats: ['XML'],
    author: 'Greenbone Networks',
    website: 'https://www.openvas.org',
    capabilities: ['Open source scanning', 'Vulnerability management'],
    description: 'Open source vulnerability scanner',
  },
  {
    name: 'Qualys',
    version: '8.0',
    formats: ['XML', 'JSON'],
    author: 'Qualys Inc.',
    website: 'https://www.qualys.com',
    capabilities: ['Cloud-based scanning', 'Compliance management'],
    description: 'Cloud-based security platform',
  },
];

const renderComponent = (props = {}) => {
  return render(
    <ThemeProvider>
      <ScannerIntegration {...props} />
    </ThemeProvider>
  );
};

describe('ScannerIntegration', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (getSupportedScanners as jest.Mock).mockResolvedValue(mockScanners);
    (uploadParserFile as jest.Mock).mockResolvedValue({ success: true });
  });

  describe('Component Rendering', () => {
    it('renders the scanner integration component', () => {
      renderComponent();

      expect(screen.getByText('Scanner Integration')).toBeInTheDocument();
      expect(screen.getByText('Supported Scanners')).toBeInTheDocument();
      expect(screen.getByText('Upload Scan Results')).toBeInTheDocument();
    });

    it('renders scanner cards for each supported scanner', async () => {
      renderComponent();

      await waitFor(() => {
        expect(screen.getByText('Nessus')).toBeInTheDocument();
        expect(screen.getByText('OpenVAS')).toBeInTheDocument();
        expect(screen.getByText('Qualys')).toBeInTheDocument();
      });
    });

    it('displays scanner information correctly', async () => {
      renderComponent();

      await waitFor(() => {
        expect(screen.getByText('Version: 10.0')).toBeInTheDocument();
        expect(screen.getByText('Author: Tenable')).toBeInTheDocument();
        expect(screen.getByText('Formats: XML, CSV')).toBeInTheDocument();
      });
    });
  });

  describe('Scanner Information Display', () => {
    it('shows scanner capabilities', async () => {
      renderComponent();

      await waitFor(() => {
        expect(screen.getByText('Network scanning')).toBeInTheDocument();
        expect(screen.getByText('Vulnerability assessment')).toBeInTheDocument();
        expect(screen.getByText('Open source scanning')).toBeInTheDocument();
      });
    });

    it('displays scanner website links', async () => {
      renderComponent();

      await waitFor(() => {
        const tenableLink = screen.getByText('https://www.tenable.com');
        const openvasLink = screen.getByText('https://www.openvas.org');
        const qualysLink = screen.getByText('https://www.qualys.com');

        expect(tenableLink).toBeInTheDocument();
        expect(openvasLink).toBeInTheDocument();
        expect(qualysLink).toBeInTheDocument();
      });
    });

    it('shows scanner descriptions', async () => {
      renderComponent();

      await waitFor(() => {
        expect(screen.getByText('Professional vulnerability scanner')).toBeInTheDocument();
        expect(screen.getByText('Open source vulnerability scanner')).toBeInTheDocument();
        expect(screen.getByText('Cloud-based security platform')).toBeInTheDocument();
      });
    });
  });

  describe('Scanner Card Interactions', () => {
    it('expands scanner details when clicked', async () => {
      const user = userEvent.setup();
      renderComponent();

      await waitFor(() => {
        const nessusCard = screen.getByText('Nessus').closest('div');
        expect(nessusCard).toBeInTheDocument();
      });

      const expandButton = screen.getByText('Nessus').closest('div')?.querySelector('button');
      if (expandButton) {
        await user.click(expandButton);
      }

      await waitFor(() => {
        expect(screen.getByText('Capabilities:')).toBeInTheDocument();
        expect(screen.getByText('Network scanning')).toBeInTheDocument();
        expect(screen.getByText('Vulnerability assessment')).toBeInTheDocument();
      });
    });

    it('collapses scanner details when clicked again', async () => {
      const user = userEvent.setup();
      renderComponent();

      await waitFor(() => {
        const nessusCard = screen.getByText('Nessus').closest('div');
        expect(nessusCard).toBeInTheDocument();
      });

      const expandButton = screen.getByText('Nessus').closest('div')?.querySelector('button');
      if (expandButton) {
        await user.click(expandButton);
        await user.click(expandButton);
      }

      await waitFor(() => {
        expect(screen.queryByText('Capabilities:')).not.toBeInTheDocument();
      });
    });

    it('shows different badges for different scanner types', async () => {
      renderComponent();

      await waitFor(() => {
        // Check for professional badge
        expect(screen.getByText('Professional')).toBeInTheDocument();
        // Check for open source badge
        expect(screen.getByText('Open Source')).toBeInTheDocument();
        // Check for cloud badge
        expect(screen.getByText('Cloud')).toBeInTheDocument();
      });
    });
  });

  describe('File Upload Functionality', () => {
    it('renders file upload area', () => {
      renderComponent();

      expect(screen.getByText('Upload Scan Results')).toBeInTheDocument();
      expect(screen.getByText('Drag and drop scan result files here')).toBeInTheDocument();
      expect(screen.getByText('or click to browse')).toBeInTheDocument();
    });

    it('handles file selection via click', async () => {
      const user = userEvent.setup();
      renderComponent();

      const file = new File(['test content'], 'test_scan.xml', { type: 'application/xml' });
      const fileInput = screen.getByLabelText(/upload/i);

      await user.upload(fileInput, file);

      await waitFor(() => {
        expect(uploadParserFile).toHaveBeenCalled();
      });
    });

    it('handles drag and drop file upload', async () => {
      renderComponent();

      const file = new File(['test content'], 'test_scan.xml', { type: 'application/xml' });
      const dropZone = screen.getByText('Drag and drop scan result files here').closest('div');

      if (dropZone) {
        fireEvent.drop(dropZone, {
          dataTransfer: {
            files: [file],
          },
        });
      }

      await waitFor(() => {
        expect(uploadParserFile).toHaveBeenCalled();
      });
    });

    it('shows upload progress', async () => {
      const user = userEvent.setup();
      renderComponent();

      const file = new File(['test content'], 'test_scan.xml', { type: 'application/xml' });
      const fileInput = screen.getByLabelText(/upload/i);

      await user.upload(fileInput, file);

      await waitFor(() => {
        expect(screen.getByText('Processing...')).toBeInTheDocument();
      });
    });

    it('handles multiple file uploads', async () => {
      const user = userEvent.setup();
      renderComponent();

      const file1 = new File(['test content 1'], 'test_scan1.xml', { type: 'application/xml' });
      const file2 = new File(['test content 2'], 'test_scan2.csv', { type: 'text/csv' });
      const fileInput = screen.getByLabelText(/upload/i);

      await user.upload(fileInput, [file1, file2]);

      await waitFor(() => {
        expect(uploadParserFile).toHaveBeenCalledTimes(2);
      });
    });

    it('validates file types', async () => {
      const user = userEvent.setup();
      renderComponent();

      const invalidFile = new File(['test content'], 'test.txt', { type: 'text/plain' });
      const fileInput = screen.getByLabelText(/upload/i);

      await user.upload(fileInput, invalidFile);

      await waitFor(() => {
        expect(screen.getByText('Invalid file type')).toBeInTheDocument();
      });
    });

    it('handles upload errors gracefully', async () => {
      const user = userEvent.setup();
      (uploadParserFile as jest.Mock).mockRejectedValue(new Error('Upload failed'));
      renderComponent();

      const file = new File(['test content'], 'test_scan.xml', { type: 'application/xml' });
      const fileInput = screen.getByLabelText(/upload/i);

      await user.upload(fileInput, file);

      await waitFor(() => {
        expect(screen.getByText('Upload failed')).toBeInTheDocument();
      });
    });
  });

  describe('Scanner Selection', () => {
    it('allows selecting scanner type for upload', async () => {
      const user = userEvent.setup();
      renderComponent();

      const scannerSelect = screen.getByText('Select Scanner');
      await user.click(scannerSelect);

      await waitFor(() => {
        expect(screen.getByText('Nessus')).toBeInTheDocument();
        expect(screen.getByText('OpenVAS')).toBeInTheDocument();
        expect(screen.getByText('Qualys')).toBeInTheDocument();
      });

      const nessusOption = screen.getByText('Nessus');
      await user.click(nessusOption);

      await waitFor(() => {
        expect(screen.getByText('Selected: Nessus')).toBeInTheDocument();
      });
    });

    it('passes selected scanner to upload function', async () => {
      const user = userEvent.setup();
      renderComponent();

      // Select scanner
      const scannerSelect = screen.getByText('Select Scanner');
      await user.click(scannerSelect);

      const nessusOption = screen.getByText('Nessus');
      await user.click(nessusOption);

      // Upload file
      const file = new File(['test content'], 'test_scan.xml', { type: 'application/xml' });
      const fileInput = screen.getByLabelText(/upload/i);

      await user.upload(fileInput, file);

      await waitFor(() => {
        expect(uploadParserFile).toHaveBeenCalledWith(
          expect.any(FormData),
          'nessus'
        );
      });
    });
  });

  describe('Upload Status and Feedback', () => {
    it('shows success message after successful upload', async () => {
      const user = userEvent.setup();
      (uploadParserFile as jest.Mock).mockResolvedValue({
        success: true,
        processed_count: 5,
        vulnerabilities: ['vuln1', 'vuln2'],
      });
      renderComponent();

      const file = new File(['test content'], 'test_scan.xml', { type: 'application/xml' });
      const fileInput = screen.getByLabelText(/upload/i);

      await user.upload(fileInput, file);

      await waitFor(() => {
        expect(screen.getByText('Upload successful!')).toBeInTheDocument();
        expect(screen.getByText('Processed 5 vulnerabilities')).toBeInTheDocument();
      });
    });

    it('shows processing status during upload', async () => {
      const user = userEvent.setup();
      (uploadParserFile as jest.Mock).mockImplementation(() => new Promise(resolve => setTimeout(resolve, 100)));
      renderComponent();

      const file = new File(['test content'], 'test_scan.xml', { type: 'application/xml' });
      const fileInput = screen.getByLabelText(/upload/i);

      await user.upload(fileInput, file);

      await waitFor(() => {
        expect(screen.getByText('Processing...')).toBeInTheDocument();
      });
    });

    it('shows error details when upload fails', async () => {
      const user = userEvent.setup();
      (uploadParserFile as jest.Mock).mockRejectedValue(new Error('Invalid file format'));
      renderComponent();

      const file = new File(['test content'], 'test_scan.xml', { type: 'application/xml' });
      const fileInput = screen.getByLabelText(/upload/i);

      await user.upload(fileInput, file);

      await waitFor(() => {
        expect(screen.getByText('Upload failed')).toBeInTheDocument();
        expect(screen.getByText('Invalid file format')).toBeInTheDocument();
      });
    });
  });

  describe('Scanner Information Modal', () => {
    it('opens scanner information modal when info button is clicked', async () => {
      const user = userEvent.setup();
      renderComponent();

      await waitFor(() => {
        const infoButtons = screen.getAllByLabelText(/information/i);
        expect(infoButtons.length).toBeGreaterThan(0);
      });

      const infoButton = screen.getAllByLabelText(/information/i)[0];
      await user.click(infoButton);

      await waitFor(() => {
        expect(screen.getByText('Scanner Information')).toBeInTheDocument();
        expect(screen.getByText('Nessus')).toBeInTheDocument();
        expect(screen.getByText('Professional vulnerability scanner')).toBeInTheDocument();
      });
    });

    it('closes scanner information modal', async () => {
      const user = userEvent.setup();
      renderComponent();

      await waitFor(() => {
        const infoButtons = screen.getAllByLabelText(/information/i);
        expect(infoButtons.length).toBeGreaterThan(0);
      });

      const infoButton = screen.getAllByLabelText(/information/i)[0];
      await user.click(infoButton);

      await waitFor(() => {
        expect(screen.getByText('Scanner Information')).toBeInTheDocument();
      });

      const closeButton = screen.getByText('Close');
      await user.click(closeButton);

      await waitFor(() => {
        expect(screen.queryByText('Scanner Information')).not.toBeInTheDocument();
      });
    });
  });

  describe('Error Handling', () => {
    it('handles API errors when loading scanners', async () => {
      (getSupportedScanners as jest.Mock).mockRejectedValue(new Error('Failed to load scanners'));
      renderComponent();

      await waitFor(() => {
        expect(screen.getByText('Error loading supported scanners')).toBeInTheDocument();
      });
    });

    it('shows loading state while fetching scanners', () => {
      (getSupportedScanners as jest.Mock).mockImplementation(() => new Promise(() => {}));
      renderComponent();

      expect(screen.getByText('Loading supported scanners...')).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('has proper ARIA labels', () => {
      renderComponent();

      expect(screen.getByLabelText(/upload/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/select scanner/i)).toBeInTheDocument();
    });

    it('supports keyboard navigation', async () => {
      const user = userEvent.setup();
      renderComponent();

      const fileInput = screen.getByLabelText(/upload/i);
      fileInput.focus();

      await user.keyboard('{Enter}');

      // Should trigger file selection dialog
      expect(fileInput).toHaveFocus();
    });
  });

  describe('Responsive Design', () => {
    it('adapts to different screen sizes', () => {
      renderComponent();

      // Test that the component renders without errors on different screen sizes
      expect(screen.getByText('Scanner Integration')).toBeInTheDocument();
    });
  });

  describe('File Type Validation', () => {
    it('accepts valid file types', async () => {
      const user = userEvent.setup();
      renderComponent();

      const validFiles = [
        new File(['content'], 'scan.xml', { type: 'application/xml' }),
        new File(['content'], 'scan.csv', { type: 'text/csv' }),
        new File(['content'], 'scan.json', { type: 'application/json' }),
      ];

      const fileInput = screen.getByLabelText(/upload/i);

      for (const file of validFiles) {
        await user.upload(fileInput, file);
        await waitFor(() => {
          expect(uploadParserFile).toHaveBeenCalled();
        });
      }
    });

    it('rejects invalid file types', async () => {
      const user = userEvent.setup();
      renderComponent();

      const invalidFiles = [
        new File(['content'], 'scan.txt', { type: 'text/plain' }),
        new File(['content'], 'scan.pdf', { type: 'application/pdf' }),
        new File(['content'], 'scan.doc', { type: 'application/msword' }),
      ];

      const fileInput = screen.getByLabelText(/upload/i);

      for (const file of invalidFiles) {
        await user.upload(fileInput, file);
        await waitFor(() => {
          expect(screen.getByText('Invalid file type')).toBeInTheDocument();
        });
      }
    });
  });
});
