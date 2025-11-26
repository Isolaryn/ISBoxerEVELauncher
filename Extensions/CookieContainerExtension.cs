using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Reflection;

namespace ISBoxerEVELauncher.Extensions
{
    public static class CookieContainerExtension
    {
        public static IEnumerable<Cookie> GetAllCookies(this CookieContainer c)
        {
            Hashtable k = (Hashtable) c.GetType().GetField("m_domainTable", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(c)
                ?? throw new System.Exception("Could not get m_domainTable from CookieContainer");
            foreach (DictionaryEntry element in k)
            {
                SortedList l = (SortedList)element.Value.GetType().GetField("m_list", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(element.Value)
                    ?? throw new System.Exception("Could not get m_list from CookieContainer domain entry");
                foreach (var e in l)
                {
                    var cl = (CookieCollection)((DictionaryEntry)e).Value;
                    foreach (Cookie fc in cl)
                    {
                        yield return fc;
                    }
                }
            }
        }
    }
}