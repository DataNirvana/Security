using System;
using System.Collections.Generic;
using System.Text;

namespace MGL.Security
{
    public class ContentItem
    {
        #region !--- Properties ---!
        private int id;
        public int ID
        {
            get { return id; }
            set { id = value; }
        }
        private SecureRequestContext.ContentType typeOfContent;
        public SecureRequestContext.ContentType TypeOfContent
        {
            get { return typeOfContent; }
            set { typeOfContent = value; }
        }

        private string name;
        public string Name
        {
            get { return name; }
            set { name = value; }
        }

        private string description;
        public string Description
        {
            get { return description; }
            set { description = value; }
        }

        private int parentID = -1;
        /// <summary>
        /// THis is a hack to get the theme content type working
        /// Currently themes are represented in the Security UI
        /// as one element for a parent-child combination.
        /// We can use this method to store a parent id so that it too
        /// can be added to the cross reference tables rather than
        /// just the child ids! (avoid properties just in case this use refelction anywhere)
        /// </summary>
        /// <returns></returns>
        public int GetParentID()
        {
            return parentID;
        }
        /// <summary>
        /// THis is a hack to get the theme content type working
        /// Currently themes are represented in the Security UI
        /// as one element for a parent-child combination.
        /// We can use this method to store a parent id so that it too
        /// can be added to the cross reference tables rather than
        /// just the child ids!
        /// </summary>
        /// <returns></returns>
        public void SetParentID(int val)
        {
            parentID = val;
        }
        #endregion

        #region !--- Constructor ---!
        public ContentItem()
        {
        }
        #endregion
    }
}
