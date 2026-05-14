using ISBoxerEVELauncher.Games.EVE;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Windows;

namespace ISBoxerEVELauncher.Windows
{
    public partial class ImportFromEVELauncherWindow : Window
    {
        private bool _suppressSync;

        public ImportFromEVELauncherWindow(IEnumerable<ImportCandidate> candidates, IEnumerable<EVEAccount> existingAccounts)
        {
            var existing = existingAccounts ?? new EVEAccount[0];
            Rows = new ObservableCollection<ImportRow>();
            foreach (var c in candidates)
            {
                bool overwrites = existing.Any(a => !string.IsNullOrEmpty(a.Username)
                    && a.Username.Equals(c.Username, StringComparison.InvariantCultureIgnoreCase));
                var row = new ImportRow
                {
                    Candidate = c,
                    Username = c.Username,
                    ActionText = overwrites ? "Overwrite existing" : "New account",
                    IsSelected = !overwrites,
                };
                row.PropertyChanged += Row_PropertyChanged;
                Rows.Add(row);
            }
            InitializeComponent();
            UpdateHeaderCheckState();
        }

        private void Row_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == "IsSelected") UpdateHeaderCheckState();
        }

        private void UpdateHeaderCheckState()
        {
            if (_suppressSync || checkAll == null) return;
            int total = Rows.Count;
            int selected = Rows.Count(r => r.IsSelected);
            _suppressSync = true;
            try
            {
                checkAll.IsChecked = (total > 0 && selected == total);
            }
            finally { _suppressSync = false; }
        }

        private void SetAllSelected(bool value)
        {
            if (_suppressSync) return;
            _suppressSync = true;
            try
            {
                foreach (var r in Rows) r.IsSelected = value;
            }
            finally { _suppressSync = false; }
        }

        private void checkAll_Checked(object sender, RoutedEventArgs e)
        {
            SetAllSelected(true);
        }

        private void checkAll_Unchecked(object sender, RoutedEventArgs e)
        {
            SetAllSelected(false);
        }

        public ObservableCollection<ImportRow> Rows { get; }

        public IReadOnlyList<ImportCandidate> SelectedCandidates
        {
            get { return Rows.Where(r => r.IsSelected).Select(r => r.Candidate).ToList(); }
        }

        private void buttonImport_Click(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            if (!Rows.Any(r => r.IsSelected))
            {
                MessageBox.Show("Select at least one account to import.");
                return;
            }
            DialogResult = true;
            Close();
        }

        private void buttonCancel_Click(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            DialogResult = false;
            Close();
        }

        public class ImportRow : INotifyPropertyChanged
        {
            private bool _isSelected;
            public ImportCandidate Candidate { get; set; }
            public string Username { get; set; }
            public string ActionText { get; set; }
            public bool IsSelected
            {
                get { return _isSelected; }
                set
                {
                    if (_isSelected == value) return;
                    _isSelected = value;
                    var h = PropertyChanged;
                    if (h != null) h(this, new PropertyChangedEventArgs("IsSelected"));
                }
            }
            public event PropertyChangedEventHandler PropertyChanged;
        }
    }
}
