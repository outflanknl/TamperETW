using System.Windows.Forms;

namespace dllNamespace
{
    public class dllClass
    {
        public static int ShowMsg(string msg)
        {
            MessageBox.Show(msg);
            return 0;
        }
    }
}
