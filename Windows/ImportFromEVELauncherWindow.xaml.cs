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
        public ImportFromEVELauncherWindow(IEnumerable<ImportCandidate> candidates, IEnumerable<EVEAccount> existingAccounts)
        {
            var existing = existingAccounts ?? new EVEAccount[0];
            Rows = new ObservableCollection<ImportRow>();
            foreach (var c in candidates)
            {
                bool overwrites = existing.Any(a => !string.IsNullOrEmpty(a.Username)
                    && a.Username.Equals(c.Username, StringComparison.InvariantCultureIgnoreCase));
                Rows.Add(new ImportRow
                {
                    Candidate = c,
                    Username = c.Username,
                    ActionText = overwrites ? "Overwrite existing" : "New account",
                    IsSelected = !overwrites,
                });
            }
            InitializeComponent();
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
