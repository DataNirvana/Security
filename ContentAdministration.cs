using System;
using System.Collections.Generic;
using System.Text;
using MGL.Data.DataUtilities;
using System.Web.UI.WebControls;
using System.Data;
using MGL.DomainModel;
using DataNirvana.Database;

namespace MGL.Security
{
    public class ContentAdministration
    {
        #region !--- Properties ---!
        protected ConfigurationInfo lcf;
        public ConfigurationInfo Lcf
        {
            get { return lcf; }
            set { lcf = value; }
        }

        private DatabaseWrapper dbInfo;
        public DatabaseWrapper DbInfo
        {
            get { return dbInfo; }
            set { dbInfo = value; }
        }
        #endregion

        #region !--- Constructor ---!


        public ContentAdministration(ConfigurationInfo lcf)
        {
            this.Lcf = lcf;
        }

        #endregion


        #region Static Methods

        public static bool RefreshContentTable()
        {
            // Default is to refresh the content table in the staging DB as this is where content changes.
            return RefreshContentTable(AppSecurityContext.StagingDbLcf);
        }

        public static bool RefreshContentTable(ConfigurationInfo lcf)
        {
            bool isSuccess = false;

            // Use a private DB object to avoid contention with the object variable.
            DatabaseWrapper db = null;
            ContentAdministration contentHelper = null;
            try
            {

                // Use the staging DB config as that is where new content appears.
                db = new DatabaseWrapper(lcf);
                contentHelper = new ContentAdministration(lcf);
                db.Connect();

                // 1. Ensure the content table exists

                bool isExisting = db.TableExists(BaseSecurityOperations.tnContent);
                if (!isExisting)
                {
                    Logger.LogError(5, "Content table " + BaseSecurityOperations.tnContent + " does not exist, please ensure that it does!");
                    return false;
                }

                // TODO: Remove this old code as we now do not rebuild the content table, just add new items and remove deleted ones.
                //// 2. Clear the content table (or optionally create it, if it does not? Not enough time time for in this release).
                //sLogger.Log("Clearing the content table (" + BaseSecurityOperations.tnContent + ") ..."); ;
                //bool isCleared = db.ClearTable(BaseSecurityOperations.tnContent);
                //if (!isCleared || db.GetCount(BaseSecurityOperations.tnContent) > 0)
                //{
                //    sLogger.LogError("Failed to clear content table " + BaseSecurityOperations.tnContent + ", abandoning refreshing the content table!");
                //    return false;
                //}
                //sLogger.Log("Content table cleared."); ;

                //int updates = db.ExecuteUpdate("ALTER TABLE " + BaseSecurityOperations.tnContent + @" AUTO_INCREMENT=1");

                // 3. Get a data structure containing the content types
                // TODO: ask Maz about this.
                List<MGL.Security.ContentType> contentTypes = contentHelper.GetAllContentsTypes();
                if (contentTypes == null)
                {
                    Logger.LogError(5, "Failed to get list of all content types, abandoning refreshing content table!");
                    return false;
                }
                if (contentTypes.Count == 0)
                {
                    Logger.LogWarning("Got an empty list of all content types, skipping refreshing content table. Is the content type table empty, and if so, should it be populated?");
                    return true;
                }

                // 4. Loop over the content types calling a method to populate the content table.
                bool isAllPopulated = true;
                foreach (MGL.Security.ContentType contentType in contentTypes)
                {
                    if (contentType == null)
                    {
                        Logger.LogError(5, "NUll contentType detected, skipping it ...");
                        continue;
                    }

                    bool isPopulated = RefreshContentTable(db, BaseSecurityOperations.tnContent, contentType);
                    if (!isPopulated)
                    {
                        Logger.LogError(5, "Failed to populate content table " + BaseSecurityOperations.tnContent + " with content type " + contentType.ContentName + "!");
                        isAllPopulated = false;
                    }
                }

                bool isXrefsCleaned = CleanupContentXRefs(db, BaseSecurityOperations.tnContent, BaseSecurityOperations.tnXrefGroupsContent);

                isSuccess = isAllPopulated;
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Problem refreshing content table at " + ex);
                Logger.LogError(5, "Please correct this as otherwise the content in the security admin GUI may be outdated!");
                isSuccess = false;
            }
            finally
            {
                if (db != null)
                    db.Disconnect();
            }

            return isSuccess;
        }

        protected static bool RefreshContentTable(DatabaseWrapper db, string contentTable,
            MGL.Security.ContentType contentType)
        {
            bool isSuccess = false;

            string sql = null;
            try
            {
                // sLogger.Log("Inserting new content items into security content table " + contentTable + " of type " + contentType.TypeOfContent.ToString() + " ...");

                sql = ContentQB.GetInsertNewContentItemsFromSrcTblSql(contentTable, contentType);
                if (sql == null)
                {
                    Logger.LogError(5, "Failed to get SQL to insert new content items of type " + contentType.TypeOfContent.ToString() + ", cannot insert content items for this contentType!");
                    return false;
                }

                int inserts = -1;

                inserts = db.ExecuteSQL(sql, ref isSuccess);
//                isSuccess = !Logger.LogList(db.GetErrors(), "ContentAdministration", "RefreshContentTableIns");
                if (!isSuccess)
                {
                    Logger.LogError(5, "Failed to populate content table with new items of contentType " + contentType.TypeOfContent.ToString());
                    return false;
                }

                string delSql = ContentQB.GetDeleteOldContentItemsFromSrcTblSql(contentTable, contentType);
                if (delSql == null)
                {
                    Logger.LogError(5, "Failed to get SQL to delete old content items of type " + contentType.TypeOfContent.ToString() + ", cannot insert content items for this contentType!");
                    return false;
                }

                int numDels = -1;
                numDels = db.ExecuteSQL(delSql, ref isSuccess);
//                isSuccess = !Logger.LogList(db.GetErrors(), "ContentAdministration", "RefreshContentTableDels");
                if (!isSuccess)
                {
                    Logger.LogError(5, "Failed to delete old content items from content table of contentType " + contentType.TypeOfContent.ToString());
                    return false;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Failed to populate contents tables " + contentTable + " with content type " + contentType.ContentName + " at " + ex);
                isSuccess = false;
            }

            return isSuccess;
        }

        protected static bool CleanupContentXRefs(DatabaseWrapper db, string contentTable, string contentsXrefTable)
        {
            bool isSuccess = false;

            try
            {
                string delXrefSql = ContentQB.GetDeleteOutdatedContentXrefs(contentTable, contentsXrefTable);
                if (delXrefSql == null)
                {
                    Logger.LogError(5, "Failed to get SQL to delete outdated contents xrefs , cannot insert content items for this contentType!");
                    return false;
                }

                int numXrefDels = -1;
                numXrefDels = db.ExecuteSQL(delXrefSql, ref isSuccess);
//                isSuccess = !Logger.LogList(db.GetErrors(), "ContentAdministration", "CleanupContentXRefs");
                if (!isSuccess)
                {
                    Logger.LogError(5, "Failed to delete outdated contents xrefs from content xrefs table " + contentsXrefTable + "!");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Failed to clean up contents xrefs from content xrefs table " + contentsXrefTable + " at " + ex);
                isSuccess = false;
            }

            finally
            {
                if (isSuccess)
                {
                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;
                }
            }

            return isSuccess;
        }


        protected static bool PopulateContentTable(DatabaseWrapper db, string contentTable,
            MGL.Security.ContentType contentType)
        {
            bool isSuccess = false;

            string sql = null;
            try
            {
                Logger.LogError(5, "Inserting content items into security content table " + contentTable + " of type " + contentType.TypeOfContent.ToString() + " ...");

                sql = ContentQB.GetInsertContentItemsFromSrcTblSql(contentTable, contentType);
                if (sql == null)
                {
                    Logger.LogError(5, "Failed to get SQL to insert content items of type " + contentType.TypeOfContent.ToString() + ", cannot insert content items for this contentType!");
                    return false;
                }

                int updates = db.ExecuteSQL(sql, ref isSuccess);
//                isSuccess = !Logger.LogList(db.GetErrors(), "ContentAdministration", "PopulateContentTable");
                if (!isSuccess)
                {
                    Logger.LogError(5, "Failed to populate content table with contentType " + contentType.TypeOfContent.ToString());
                    return false;
                }

                if (updates == 0)
                {
                    Logger.LogWarning("Inserted Zero (0) content items for contentType " + contentType.TypeOfContent.ToString() + ". Please check this is correct!");
                }
                else if (updates > 0)
                {
                    Logger.Log("Successfully inserted " + updates + " content items for contentType " + contentType.TypeOfContent.ToString() + ".");
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Failed to populate content table " + contentTable + " with content type " + contentType.ContentName + " at " + ex);
                isSuccess = false;
            }

            return isSuccess;
        }

        #endregion

        #region !--- Public Methods ---!

        public List<ListItem> GetAllContentsTypesAsListItems()
        {
            List<ListItem> result = null;
            List<MGL.Security.ContentType> contentTypes = null;
//            string sql = "";
            try
            {
                //Get all contents from DAB
                contentTypes = new List<MGL.Security.ContentType>();
                contentTypes = GetAllContentsTypes();
                if (contentTypes == null || contentTypes.Count < 1)
                {
                    Logger.LogError(5, "Failed to get all contents from system. Quitting !");
                    return null;
                }
                else if (contentTypes.Count < 1)
                {
                    Logger.LogWarning("Got empty list of all contents from system. Please check this is correct !");
                    return new List<ListItem>();
                }

                result = GetContentTypeInfoAsListItem(contentTypes);
                if (result == null)
                {
                    Logger.LogError(5, "Failed to get all contents as list items from system. Quitting !");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error getting All Contents from system and converting them into a list item at: " + ex);
                return null;
            }

            return result;
        }

        public List<MGL.Security.ContentType> GetAllContentsTypes()
        {
            List<MGL.Security.ContentType> result = new List<MGL.Security.ContentType>();
            string sql = "";

            try
            {
                sql = ContentQB.GetSelectContentTypesSql("");
                DbInfo = new DatabaseWrapper(Lcf);
                DbInfo.Connect();

                string strContentID = null;
                int contentID = -1;
                IDataReader reader = DbInfo.RunSqlReader(sql);
                while (reader.Read())
                {
                    strContentID = null;
                    contentID = -1;

                    MGL.Security.ContentType content = new MGL.Security.ContentType();

                    if (reader[ContentQB.CONTENT_ID_COL] != System.DBNull.Value)
                    {
                        strContentID = reader[ContentQB.CONTENT_ID_COL].ToString();
                        if (!int.TryParse(strContentID, out contentID))
                            contentID = -1;
                    }
                    content.ID = contentID;
                    if ((string)reader[ContentQB.CONTENT_DISPLAYVAL_COL] != null)
                    {
                        content.ContentName = (string)reader[ContentQB.CONTENT_DISPLAYVAL_COL];
                    }
                    else
                    {
                        Logger.LogWarning("Null or empty Content Name is found for ID =" + content.ID + ". Please check the database!");
                        content.ContentName = null;
                    }
                    if ((string)reader[ContentQB.CONTENT_ENUMVAL_COL] != null)
                    {
                        content.TypeOfContent = (SecureRequestContext.ContentType)Enum.Parse(typeof(SecureRequestContext.ContentType), (string)reader[ContentQB.CONTENT_ENUMVAL_COL]);
                    }
                    else
                    {
                        content.TypeOfContent = SecureRequestContext.ContentType.UNKNOWN;
                    }
                    if ((string)reader[ContentQB.CONTENT_SRC_TBL_COL] != null)
                    {
                        content.ContentSourceTable = (string)reader[ContentQB.CONTENT_SRC_TBL_COL];
                    }
                    else
                    {
                        Logger.LogWarning("Null or empty Content Source Table name is found for ID =" + content.ID + ". Please check the database!");
                        content.ContentSourceTable = null;
                    }
                    if ((string)reader[ContentQB.CONTENT_ITEM_IDCOL_NAME] != null)
                    {
                        content.ContentSrcIDCol = (string)reader[ContentQB.CONTENT_ITEM_IDCOL_NAME];
                    }
                    else
                    {
                        Logger.LogWarning("Null or empty Content Source ID Column Name is found for ID =" + content.ID + ". Please check the database!");
                        content.ContentSrcIDCol = null;
                    }
                    if ((string)reader[ContentQB.CONTENT_ITEM_NAMECOL_NAME] != null)
                    {
                        content.ContentSrcNameCol = (string)reader[ContentQB.CONTENT_ITEM_NAMECOL_NAME];
                    }
                    else
                    {
                        Logger.LogWarning("Null or empty Content Source Name Column Name is found for ID =" + content.ID + ". Please check the database!");
                        content.ContentSrcNameCol = null;
                    }
                    if ((string)reader[ContentQB.CONTENT_ITEM_PARENTNAMECOL_NAME] != null)
                    {
                        content.ContentSrcParentNameCol = (string)reader[ContentQB.CONTENT_ITEM_PARENTNAMECOL_NAME];
                    }
                    else
                    {
                        Logger.LogWarning("Null or empty Content Source Parent Name Column Name is found for ID =" + content.ID + ". Please check the database!");
                        content.ContentSrcParentNameCol = null;
                    }
                    result.Add(content);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error getting all content types present in the system at: " + ex);
                return null;
            }
            finally
            {
                if (DbInfo != null)
                    DbInfo.Disconnect();
            }
            return result;
        }

        public List<ListItem> GetContentTypeInfoAsListItem(List<MGL.Security.ContentType> contents)
        {
            List<ListItem> result = null;
            try
            {
                if (contents == null)
                {
                    Logger.LogError(5, "Null of empty list of contents provided.");
                    return null;
                }

                result = new List<ListItem>();

                if (contents.Count == 0)
                {
                    return result;
                }

                foreach (MGL.Security.ContentType content in contents)
                {
                    ListItem li = new ListItem();
                    li.Value = content.ID.ToString();
                    li.Text = content.ContentName;
                    result.Add(li);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error creating a List<ListItem> from a list of contents at" + ex);
                return null;
            }

            return result;
        }

        public MGL.Security.ContentType GetContentType(int id)
        {
            MGL.Security.ContentType result = new MGL.Security.ContentType();
            string sql = "";
            string strContentID = null;
            int contentID = -1;
            try
            {
                sql = ContentQB.GetSelectContentTypesSql(id.ToString());
                DbInfo = new DatabaseWrapper(Lcf);
                DbInfo.Connect();

                IDataReader reader = DbInfo.RunSqlReader(sql);
                while (reader.Read())
                {
                    if (reader[ContentQB.CONTENT_ID_COL] != System.DBNull.Value)
                    {
                        strContentID = reader[ContentQB.CONTENT_ID_COL].ToString();
                        if (!int.TryParse(strContentID, out contentID))
                            contentID = -1;
                    }
                    result.ID = contentID;
                    if ((string)reader[ContentQB.CONTENT_DISPLAYVAL_COL] != null)
                    {
                        result.ContentName = (string)reader[ContentQB.CONTENT_DISPLAYVAL_COL];
                    }
                    else
                    {
                        Logger.LogWarning("Null or empty Content Name is found for ID =" + result.ID + ". Please check the database!");
                        result.ContentName = null;
                    }
                    if ((string)reader[ContentQB.CONTENT_ENUMVAL_COL] != null)
                    {
                        result.TypeOfContent = (SecureRequestContext.ContentType)Enum.Parse(typeof(SecureRequestContext.ContentType), (string)reader[ContentQB.CONTENT_ENUMVAL_COL]);
                    }
                    else
                    {
                        result.TypeOfContent = SecureRequestContext.ContentType.UNKNOWN;
                    }
                    if ((string)reader[ContentQB.CONTENT_SRC_TBL_COL] != null)
                    {
                        result.ContentSourceTable = (string)reader[ContentQB.CONTENT_SRC_TBL_COL];
                    }
                    else
                    {
                        Logger.LogWarning("Null or empty Content Source Table name is found for ID =" + result.ID + ". Please check the database!");
                        result.ContentSourceTable = null;
                    }
                    if ((string)reader[ContentQB.CONTENT_ITEM_IDCOL_NAME] != null)
                    {
                        result.ContentSrcIDCol = (string)reader[ContentQB.CONTENT_ITEM_IDCOL_NAME];
                    }
                    else
                    {
                        Logger.LogWarning("Null or empty Content Source ID Column Name is found for ID =" + result.ID + ". Please check the database!");
                        result.ContentSrcIDCol = null;
                    }
                    if ((string)reader[ContentQB.CONTENT_ITEM_NAMECOL_NAME] != null)
                    {
                        result.ContentSrcNameCol = (string)reader[ContentQB.CONTENT_ITEM_NAMECOL_NAME];
                    }
                    else
                    {
                        Logger.LogWarning("Null or empty Content Source Name Column Name is found for ID =" + result.ID + ". Please check the database!");
                        result.ContentSrcNameCol = null;
                    }
                    if ((string)reader[ContentQB.CONTENT_ITEM_PARENTNAMECOL_NAME] != null)
                    {
                        result.ContentSrcParentNameCol = (string)reader[ContentQB.CONTENT_ITEM_PARENTNAMECOL_NAME];
                    }
                    else
                    {
                        Logger.LogWarning("Null or empty Content Source Parent Name Column Name is found for ID =" + result.ID + ". Please check the database!");
                        result.ContentSrcParentNameCol = null;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error getting all content types present in the system at: " + ex);
                return null;
            }
            finally
            {
                if (DbInfo != null)
                    DbInfo.Disconnect();
            }
            return result;
        }


        /// <summary>
        /// Get Ids of Contents associated to a group.
        /// </summary>
        /// <param name="group">Selected Group.</param>
        /// <param name="contentType">Type of content (Report, stat, geog etc</param>
        /// <param name="associationTypes">Assigned, UnAssigned or NoAssigned</param>
        /// <returns>List of Ids of contents.</returns>
        public List<int> GetContentsIDs(MGGroup group, MGL.Security.ContentType contentType,
            GroupAdministration.AssociationTypes associationTypes)
        {
            List<int> contentIds = null;
            AppSecurityContext securityHelper = null;
            GroupPermissions thisGroupContentPerms = null;
            string msgEnd = "'" + associationTypes + "' where Group is " + group.Name + " content type is '" + contentType.TypeOfContent + "'";

            Logger.Log("Starts getting the IDs of the contents " + msgEnd);
            try
            {
                //Step 1: Get the Permission Information for the Group
                thisGroupContentPerms = new GroupPermissions();
                securityHelper = new AppSecurityContext(Lcf);
                Logger.Log("Starts getting the Permission for of Contents " + msgEnd);
                if (associationTypes == GroupAdministration.AssociationTypes.NotAssigned)
                {
                    //When a Content is Not Linked to Any Group, the Method Create a Dummy Null Group
                    //And Get the Permission for this group as the Underlying Method need a Group.
                    //It is not filtered by Content Type
                    thisGroupContentPerms = securityHelper.GetUnassignedAnyGroupPermissions();
                }
                else
                {
                    //Get the Permissions for a Group. It tells Contants Assigned or Unssigned to the Group
                    thisGroupContentPerms = securityHelper.GetGroupPermissions(group, associationTypes);
                }
                if (thisGroupContentPerms == null)
                {
                    Logger.LogError(5, "Error getting the Permission for of Contents " + msgEnd);
                    return null;
                }

                //Step ": If permissions for a group are foud, ilter the GroupContentPermissions by contentType to get the IDs for a required Contenet Type
                Logger.Log("Start filtering Group Permissions for Group " + group.Name + " to get the IDs of the Contents for Content Type '" + contentType.TypeOfContent + "'");
                contentIds = new List<int>();
                contentIds = GetFilteredContentsIds(thisGroupContentPerms.GroupContentPermissions, contentType);
                if (contentIds == null)
                {
                    Logger.Log("Error filtering Group Permissions for Group " + group.Name + " to get the IDs of the Contents for Content Type '" + contentType.TypeOfContent + "'");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "getting the IDs of the contents " + msgEnd + ex);
                return null;
            }
            return contentIds;
        }


        private List<int> GetFilteredContentsIds(List<GroupPermissions.GroupContentPermission> groupContentPerms,
            MGL.Security.ContentType contentType)
        {
            Logger.Log("Start filtering the Contents for Content Type '" + contentType.TypeOfContent + "'.");
            List<int> contentsIds = null;
            try
            {
                contentsIds = new List<int>();
                foreach (GroupPermissions.GroupContentPermission contentPermission in groupContentPerms)
                {
                    if (contentPermission.ContentType == contentType.TypeOfContent)
                    {
                        contentsIds.Add(contentPermission.ContentID);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error filtering the Contents for Content Type '" + contentType.TypeOfContent + "' at " + ex);
                return null;
            }
            return contentsIds;
        }



        /// <summary>
        /// Get a List of Content Items (Objects) give list of Ids of contents and type of content.
        /// </summary>
        /// <param name="contentsIds">Ids of the Contents to get Items for</param>
        /// <param name="contentType">Type of content</param>
        /// <returns>List of Content Items</returns>
        public List<ContentItem> GetContentItems(List<int> contentsIds, MGL.Security.ContentType contentType)
        {
            List<ContentItem> result = null;
            string strContentItemID = null;
            int contentItemID = -1;

            string sql = "";

            try
            {
                if (contentsIds == null)
                {
                    Logger.LogError(5, "Null list of content ids found. Quitting!");
                    return null;
                }
                if (contentsIds.Count == 0)
                {
                    Logger.LogWarning("Empty list of content ids found. Quitting!");
                    return null;
                }

                Logger.Log("Start getting content items (objects) given a list of content Ids (" + contentsIds.Count + ") and content type is " + contentType.TypeOfContent);

                //Getting the SQL
                sql = ContentQB.GetSelectContentItemsSQL(contentType, contentsIds);
                DbInfo = new DatabaseWrapper(Lcf);
                DbInfo.Connect();

                result = new List<ContentItem>();
                IDataReader reader = DbInfo.RunSqlReader(sql);
                if (reader == null)
                {
                    Logger.LogError(5, "Quitting, failed to get content items with sql : " + sql);
                    return null;
                }

                while (reader.Read())
                {
                    strContentItemID = null;
                    contentItemID = -1;
                    ContentItem contentItem = new ContentItem();

                    //Get Id
                    if (reader[contentType.ContentSrcIDCol] != System.DBNull.Value)
                    {
                        strContentItemID = reader[contentType.ContentSrcIDCol].ToString();
                        if (!int.TryParse(strContentItemID, out contentItemID))
                        {
                            contentItemID = -1;
                            Logger.LogError(5, "Error parsing content ID into integer. Quitting");
                            return null;
                        }
                    }
                    contentItem.ID = contentItemID;

                    //Get Name (child in case of Theme
                    if ((string)reader[contentType.ContentSrcNameCol] != null)
                    {
                        contentItem.Name = (string)reader[contentType.ContentSrcNameCol];
                    }
                    else
                    {
                        Logger.LogWarning("Null or empty Content Item Name is found for ID =" + contentItem.ID + ". Please check the database!");
                        contentItem.Name = null;
                    }
                    contentItem.TypeOfContent = contentType.TypeOfContent;


                    ////Get Name (Parent - Child in case parent is present
                    if (contentType.ContentSrcParentNameCol != null && contentType.ContentSrcParentNameCol != "")
                    {
                        if (reader[contentType.ContentSrcParentNameCol] != System.DBNull.Value)
                        {
                            //Add to list if only Parent - Child content items are present
                            string parentName = (string)reader[contentType.ContentSrcParentNameCol];
                            contentItem.Name = parentName + " - " + contentItem.Name;

                            int parentID = -1;

                            if (reader[ContentQB.THEME_PARENT_ID_COL] != System.DBNull.Value)
                            {
                                int.TryParse(reader[ContentQB.THEME_PARENT_ID_COL].ToString(), out parentID);

                                contentItem.SetParentID(parentID);
                            }

                            result.Add(contentItem);
                        }
                        else
                        {
                            // result.Add(contentItem);
                            // Skipping if a theme has not parent content item name, this imlplies that it is the Top Parent content item and is not shown on the front end
                            // Logger.LogWarning("Null or empty Content Item Parent Name is found for ID =" + contentItem.ID + ". It could be the parent content item.");
                        }
                    }
                    else
                    {
                        result.Add(contentItem);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error getting all content items for " + contentType.ContentName + " at: " + ex);
                return null;
            }
            finally
            {
                if (DbInfo != null)
                    DbInfo.Disconnect();
            }
            return result;
        }


        /// <summary>
        /// Change the group association for a given user.
        /// It can assign the groups to a user and also can un assign groups linked to a user.
        /// </summary>
        /// <param name="assignedContentsIDs">These are the content IDs Assigned to the selected group.</param>
        /// <param name="contentsIDsToChange">These are the content IDs which are selected to change association for.</param>
        /// <param name="groupsIDs">Group Ids to Assign or UnAssign</param>
        /// <param name="associationType">Assign or UnAssign</param>
        /// <returns>True if successfull, false other wise</returns>
        public bool ChangeContentAssociation(List<int> assignedContentsIDs, List<int> contentsIDsToChange, MGGroup group,
            MGL.Security.ContentType contentType, GroupAdministration.AssociationTypes associationType)
        {
            bool isChangeSuccess = true;
            DbInfo = new DatabaseWrapper(Lcf);
            string sql = "";
            try
            {
                DbInfo.Connect();
                foreach (int contentId in contentsIDsToChange)
                {
                    if (associationType == GroupAdministration.AssociationTypes.Assign)
                    {
                        sql = ContentQB.GetAssignContentsToGroupSql(group.ID, contentId);
                    }
                    if (associationType == GroupAdministration.AssociationTypes.UnAssign)
                    {
                        sql = ContentQB.GetUnAssignContentsToGroupSql(group.ID, contentId);
                    }
                    int numChanged = DbInfo.ExecuteSQL(sql, ref isChangeSuccess);
                    if (numChanged == 0)
                    {
                        isChangeSuccess = false;
                    }
                }

                if (contentType.TypeOfContent == SecureRequestContext.ContentType.THEME)
                {
                    if (!ChangeAssocParentThemesOfChildrenToGroup(DbInfo, assignedContentsIDs, contentsIDsToChange, group, contentType, associationType))
                    {
                        Logger.LogError(5, "Failed to change the group association (of type " + associationType.ToString() + ") of parent themes of the given subthemes!");
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error in changing content association at: " + ex);
                isChangeSuccess = false;
            }
            finally
            {
                if (isChangeSuccess)
                {
                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;
                }

                if (DbInfo != null)
                    DbInfo.Disconnect();
            }

            return isChangeSuccess;
        }

        /// <summary>
        /// For themes, changes the group->content association for the parent themes, given a set of subtheme association changes.
        /// It carries out the following procedure:
        /// 1. When assignign subthemes, it automatically assigns the parent themes of those sub-themes (ensuring parent theme not duplicated).
        /// 2. When unassigning subthemes, it automatically removes parent theme association IF no sub-themes are still associated to that group.
        /// </summary>
        /// <param name="dbInfo">A connected database object.</param>
        /// <param name="assignedContentsIDs">These are the content IDs Assigned to the selected group.</param>
        /// <param name="contentsIDsToChange">These are the content IDs which are selected to change association for.</param>
                /// <param name="group">The Group to change the parent associations for.</param>
        /// <param name="contentType">An object describing the content type, what it's source table is and what columns are relevant.</param>
        /// <param name="associationType">The type of association change (assign or unassign).</param>
        /// <returns>True, if successful; false otherwise.</returns>
        private bool ChangeAssocParentThemesOfChildrenToGroup(DatabaseWrapper dbInfo, List<int> assignedContentsIDs,
            List<int> contentsIDsToChange, MGGroup group, MGL.Security.ContentType contentType,
            GroupAdministration.AssociationTypes associationType)
        {
            bool isSuccess = true;

            string sql = null;
            try
            {
                if (contentsIDsToChange == null)
                {
                    Logger.LogError(5, "Problem getting parent content IDs, input was NULL contentIDs ID list!");
                    return false;
                }

                if (contentsIDsToChange.Count == 0)
                {
                    return true;
                }

                if (associationType == GroupAdministration.AssociationTypes.Assign)
                {
                    // N.B. This works in terms of ContentID NOT theme IDs!
                    List<int> parentContentThemeIDs = GetParentContentIDs(dbInfo, contentType, contentsIDsToChange);
                    if (parentContentThemeIDs == null)
                    {
                        Logger.LogError(5, "Problem getting parent content theme IDs, got NULL parent content ID list!");
                        return false;
                    }

                    if (parentContentThemeIDs.Count == 0)
                    {
                        Logger.LogError(5, "Problem getting parent content theme IDs, got empty parent content ID list!");
                        return false;
                    }

                    foreach (int parentContentThemeId in parentContentThemeIDs)
                    {
                        // Don't insert group->parentContentTheme entries where they already exist.
                        if (!IsContentGroupRelationshipExisting(DbInfo, parentContentThemeId, group.ID))
                        {
                            sql = ContentQB.GetAssignContentsToGroupSql(group.ID, parentContentThemeId);

                            bool success = false;
                            int numChanged = DbInfo.ExecuteSQL(sql, ref success);
                            if (numChanged == 0)
                            {
                                Logger.LogError(5, "Failed to add relationship between group (groupID=" + group.ID + ") and parent theme content ID " + parentContentThemeId + " in xref table " + BaseSecurityOperations.tnXrefGroupsContent + ", abandoning adding assigned parent theme content IDs!");
                                return false;
                            }
                        }
                    }

                }
                else
                {
                    isSuccess = TryUnassignParentTheme(dbInfo, assignedContentsIDs, contentsIDsToChange, group, contentType);
                    if (!isSuccess)
                    {
                        Logger.LogError(5, "Failed while trying to unassign parent themes for group " + group.ID + "!");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Failed to change the group association (of type " + associationType.ToString() + ") of parent themes of the given subthemes at " + ex);

                if (sql != null)
                    Logger.LogError(5, "SQL used was " + sql);

                return false;
            }
            finally
            {
                if (isSuccess)
                {
                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;
                }
            }

            return isSuccess;
        }

        private bool TryUnassignParentTheme(DatabaseWrapper dbInfo, List<int> assignedContentsIDs,
            List<int> contentsIDsToChange, MGGroup group, MGL.Security.ContentType contentType)
        {
            bool isSuccess = true;

            Dictionary<int, List<int>> assignedThemeParentChildIDs = null;
            Dictionary<int, List<int>> changingThemeParentChildIDs = null;
            List<int> parentThemeContentIDsToDelete = null;
            string sql = null;

            try
            {
                Logger.Log("1. Getting the assigned theme parent->child ID pairs ...");
                assignedThemeParentChildIDs = GetThemeParentChildIDs(dbInfo, assignedContentsIDs, contentType);

                Logger.Log("2. Getting the changing (association) theme parent->child ID pairs ...");
                changingThemeParentChildIDs = GetThemeParentChildIDs(dbInfo, contentsIDsToChange, contentType);

                parentThemeContentIDsToDelete = GetParentThemeContentIDsToDelete(assignedThemeParentChildIDs, changingThemeParentChildIDs);
                if (parentThemeContentIDsToDelete == null)
                {
                    Logger.LogError(5, "Failed to get parent theme content IDs to delete, abandoning unassigning parent themes ...");
                    return false;
                }

                if (parentThemeContentIDsToDelete.Count == 0)
                {
                    return true;
                }

                foreach (int parentThemeContentID in parentThemeContentIDsToDelete)
                {
                    if (IsContentGroupRelationshipExisting(DbInfo, parentThemeContentID, group.ID))
                    {
                        sql = ContentQB.GetUnAssignContentsToGroupSql(group.ID, parentThemeContentID);

                        bool success = false;
                        int numChanged = DbInfo.ExecuteSQL(sql, ref success);
                        if (numChanged == 0)
                        {
                            Logger.LogError(5, "Failed to delete relationship between group (groupID=" + group.ID + ") and parent theme content ID " + parentThemeContentID + " in xref table " + BaseSecurityOperations.tnXrefGroupsContent + ", abandoning removing unassigned parent theme content IDs! Sql was " + sql);
                            return false;
                        }
                    }
                    else
                    {
                        Logger.LogError(5, "Expected group (groupID=" + group.ID + ") to be related to parent theme content ID " + parentThemeContentID + " in xref table " + BaseSecurityOperations.tnXrefGroupsContent + " but it was not!");
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Failed while trying to unassign parent themes for group " + group.ID + " at " + ex);
                isSuccess = false;

                if (sql != null)
                    Logger.LogError(5, "SQL was " + sql);
            }
            finally
            {
                if (isSuccess)
                {
                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;
                }
            }

            return isSuccess;
        }

        private List<int> GetParentThemeContentIDsToDelete(Dictionary<int, List<int>> assignedThemeParentChildIDs, Dictionary<int, List<int>> changingThemeParentChildIDs)
        {
            List<int> result = null;

            List<int> changingChildIds = null;
            List<int> assignedChildIds = null;

            try
            {
                result = new List<int>();

                foreach (int parentThemeContentID in changingThemeParentChildIDs.Keys)
                {
                    changingChildIds = changingThemeParentChildIDs[parentThemeContentID];
                    if (changingChildIds == null)
                    {
                        Logger.LogError(5, "Failed to get changing theme child Ids for parent ID " + parentThemeContentID);
                        return null;
                    }

                    assignedChildIds = assignedThemeParentChildIDs[parentThemeContentID];
                    if (changingChildIds == null)
                    {
                        Logger.LogError(5, "Failed to get assigned theme child Ids for parent ID " + parentThemeContentID);
                        return null;
                    }

                    if (assignedChildIds.Count == 0)
                    {
                        Logger.LogError(5, "Detected Zero assigned child theme IDs for parent theme ID " + parentThemeContentID);
                        return null;
                    }

                    if ((assignedChildIds.Count - changingChildIds.Count) == 0)
                    {
                        if (!result.Contains(parentThemeContentID))
                        {
                            result.Add(parentThemeContentID);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Failed in GetParentThemeContentIDsToDelete at " + ex);
                return null;
            }

            return result;
        }

        private Dictionary<int, List<int>> GetThemeParentChildIDs(DatabaseWrapper dbInfo, List<int> contentsIDs,
            MGL.Security.ContentType contentType)
        {
            Dictionary<int, List<int>> result = null;

            string sql = null;
            IDataReader reader = null;

            try
            {
                sql = ContentQB.GetSelectGetThemeParentChildIDsSql(contentsIDs, contentType);
                reader = dbInfo.RunSqlReader(sql);
                if (reader == null)
                {
                    Logger.LogError(5, "Failed to read ThemeParentChildIDs using sql " + sql);
                    return null;
                }

                int pairCount = 0;

                string strParentThemeContentID = null;
                string strSubThemeContentID = null;
                int intParentThemeContentID = -1;
                int intSubThemeContentID = -1;
                List<int> childIds = null;
                while (reader.Read())
                {
                    strParentThemeContentID = null;
                    strSubThemeContentID = null;
                    intParentThemeContentID = -1;
                    intSubThemeContentID = -1;

                    if (reader[0] != System.DBNull.Value)
                    {
                        strParentThemeContentID = reader[0].ToString();
                        if (!int.TryParse(strParentThemeContentID, out intParentThemeContentID) || intParentThemeContentID < 1)
                        {
                            Logger.LogError(5, "Error parsing parent-theme content ID as it is not a valid positive integer.");
                            return null;
                        }
                    }

                    if (reader[1] != System.DBNull.Value)
                    {
                        strSubThemeContentID = reader[1].ToString();
                        if (!int.TryParse(strSubThemeContentID, out intSubThemeContentID) || intSubThemeContentID < 1)
                        {
                            Logger.LogError(5, "Error parsing sub-theme content ID as it is not a valid positive integer.");
                            return null;
                        }
                    }

                    pairCount++;
                    if (result == null)
                        result = new Dictionary<int, List<int>>();

                    if (!result.ContainsKey(intParentThemeContentID))
                    {
                        childIds = new List<int>();
                        result.Add(intParentThemeContentID, childIds);
                    }
                    else
                    {
                        childIds = result[intParentThemeContentID];

                    }

                    if (!childIds.Contains(intSubThemeContentID))
                        childIds.Add(intSubThemeContentID);
                    else
                    {
                        Logger.LogError(5, "Duplicate sub-theme ID " + intSubThemeContentID + " detected for parent theme ID " + intParentThemeContentID + ", abandoning getting data ...");
                        return null;
                    }
                }

                if (result == null)
                {
                    Logger.LogError(5, "Failed to get theThemeParentChildIDs!");
                    return null;
                }

                if (pairCount != contentsIDs.Count)
                    Logger.LogWarning("Expected " + contentsIDs.Count + " ID pairs but actual count was " + pairCount + "!");
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error getting theme parent->child Id pairs at " + ex);
                if (sql != null)
                    Logger.LogError(5, "SQL used was " + sql);

                result = null;
            }
            finally
            {
                if (reader != null && !reader.IsClosed)
                    reader.Close();
            }

            return result;
        }

        private bool IsContentGroupRelationshipExisting(DatabaseWrapper dbInfo, int contentID, int groupID)
        {
            bool isExisting = false;

            string whereClause = null;
            try
            {
                whereClause = GroupQB.GROUP_ID_COL_XREFTBL + " = " + groupID + " AND " + GroupQB.GROUP_CONTENT_FEATUREID_COL + " = " + contentID;

                int existingRecordCount = dbInfo.GetCount(BaseSecurityOperations.tnXrefGroupsContent, whereClause);

                bool isSuccess = true; // !Logger.LogList(dbInfo.GetErrors(), "ContentAdministration", "IsContentGroupRelationshipExisting");
                if (!isSuccess)
                {
                    Logger.LogError(5, "Error checking if content group relationship already exists!");
                    return true;
                }

                if (existingRecordCount == 0)
                {
                    isExisting = false;
                }
                else if (existingRecordCount == 1)
                {
                    isExisting = true;
                }
                else
                {
                    Logger.LogError(5, "Group (groupID=" + groupID + ") to content (contentID=" + contentID + ") relation appears more than once! Please check this as the table (" + BaseSecurityOperations.tnXrefGroupsContent + ") should not contain duplication relationships!");
                    isExisting = true;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error checking if content group relationship already exists at " + ex);
                if (whereClause != null)
                    Logger.LogError(5, "Where clause used was " + whereClause);

                return true;
            }

            return isExisting;
        }

        private List<int> GetParentContentIDs(DatabaseWrapper dbInfo,
            MGL.Security.ContentType contentType, List<int> contentIDs)
        {
            List<int> parentContentIDs = null;

            string sql = null;
            try
            {
                sql = ContentQB.GetParentContentIDs(contentType, contentIDs);
                parentContentIDs = dbInfo.GetIntegerList(sql);
                if (parentContentIDs == null)
                {
                    Logger.LogError(5, "Problem getting parent content theme IDs using sql " + sql);
                    return null;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Failed to get parent content theme IDs using sql " + sql + " at " + ex);
                return null;
            }

            return parentContentIDs;
        }


        public List<int> GetSecurityContentIDs(List<int> contentsFeatureValues,
            MGL.Security.ContentType contentType)
        {
            List<int> result = null;

            if (contentsFeatureValues == null)
            {
                Logger.LogError(5, "Can not get content IDs from Null list of feature values. Quitting!");
                return null;
            }
            else if (contentsFeatureValues.Count == 0)
            {
                Logger.LogError(5, "Can not get content IDs from empty list of featue values. Quitting");
                return new List<int>();
            }

            DbInfo = new DatabaseWrapper(Lcf);
            string sql = "";
            try
            {
                sql = ContentQB.GetSelectContentIDsForContentFeaturesSql(contentsFeatureValues, contentType.TypeOfContent.ToString());

                DbInfo.Connect();

                IDataReader reader = DbInfo.RunSqlReader(sql);
                if (reader == null)
                {
                    Logger.LogError(5, "Failed to read the content IDs from database using SQL = " + sql);
                    return null;
                }

                int contentIDCount = 0;
                while (reader.Read())
                {
                    string strContentID = null;
                    int contentID = -1;
                    if (reader[ContentQB.CONTENT_ID_COL] != System.DBNull.Value)
                    {
                        strContentID = reader[ContentQB.CONTENT_ID_COL].ToString();
                        if (!int.TryParse(strContentID, out contentID) || contentID < 1)
                        {
                            Logger.LogError(5, "Error casting content ID as it is not a valid positive integer.");
                            return null;
                        }
                    }

                    contentIDCount++;
                    if (result == null)
                        result = new List<int>();

                    if (!result.Contains(contentID))
                        result.Add(contentID);
                }

                if (result == null)
                {
                    Logger.LogError(5, "Failed to get the Content IDs for the specified feature values!");
                    return null;
                }

                if (contentIDCount != contentsFeatureValues.Count)
                    Logger.LogWarning("Expected " + contentsFeatureValues.Count + " content IDs but actual count was " + contentIDCount + "!");

            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error in getting the IDs for Security Contents Items given their Feature Values at: " + ex);
                return null;
            }
            finally
            {
                if (DbInfo != null)
                    DbInfo.Disconnect();
            }
            return result;

        }


        public bool AssignContentsToGroups(List<int> contentIds, List<int> groupsIds, out string msg)
        {
            bool isAssigned = true;
            string sql = "";
            msg = "";
            Logger.Log("Start assigning '" + contentIds.Count + "' Contents to '" + groupsIds + "' Groups." );
            int totalExpectedNumber = contentIds.Count * groupsIds.Count;
            try
            {
                DbInfo = new DatabaseWrapper(Lcf);
                DbInfo.Connect();
                sql = GroupQB.GetAssignGroupToContentsSql(groupsIds, contentIds);
                bool success = false;
                int numChanged = DbInfo.ExecuteSQL(sql, ref success);
                if (numChanged == 0 || numChanged != totalExpectedNumber)
                {
                    msg = "Failed to assign '" + contentIds.Count + "' selected Contents to '"  + groupsIds.Count + "'selected Groups.";
                    Logger.LogError(5, msg);
                    return false;
                }
                msg = "Successfully assigned '" + contentIds.Count + "' selected Contents to '" + groupsIds.Count + "'selected Groups.";
            }
            catch (Exception ex)
            {
                msg = "Error assigning '" + contentIds.Count +"' Contents to '" + groupsIds.Count + "' Groups";
                Logger.LogError(5, msg + "with SQL " + sql + " at: " + ex);
                return false;
            }
            finally
            {
                if (isAssigned)
                {
                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;
                }

                if (DbInfo != null)
                    DbInfo.Disconnect();
            }
            return isAssigned;
        }






        #endregion













    }
}
