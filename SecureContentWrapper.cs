using System;
using System.Data;
using System.Configuration;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Collections.Generic;
using MGL.Data.DataUtilities;

namespace MGL.Security
{

    /// <summary>
    /// A wrapper class for providing access to secure data.
    /// </summary>
    public class SecureContentWrapper
    {

        #region InnerClasses

        public class LayerGroup
        {

            private int layerGroup_ID = -1;
            /// <summary>
            /// The unique ID from the PK of the dl_layergroups table.
            /// </summary>
            public int LayerGroup_ID
            {
                get
                {
                    return layerGroup_ID;
                }
                set
                {
                    layerGroup_ID = value;
                }
            }

            public LayerGroup()
            {
                LayerGroup_ID = -1;
            }

            public LayerGroup(int layerGroup_ID)
            {
                LayerGroup_ID = layerGroup_ID;
            }

        }

        public class Report
        {

            private int report_ID = -1;
            /// <summary>
            /// The unique ID from the PK of the reports table.
            /// </summary>
            public int Report_ID
            {
                get
                {
                    return report_ID;
                }
                set
                {
                    report_ID = value;
                }
            }

            public Report()
            {
                Report_ID = -1;
            }

            public Report(int report_ID)
            {
                Report_ID = report_ID;
            }

        }

        public class Theme
        {

            private int dlt_ID = -1;
            /// <summary>
            /// The ID of the theme (from the DLT_IT column in the reports table).
            /// </summary>
            public int Dlt_ID
            {
                get
                {
                    return dlt_ID;
                }
                set
                {
                    dlt_ID = value;
                }
            }

            public Theme()
            {
                Dlt_ID = -1;
            }

            public Theme(int dlt_ID)
            {
                Dlt_ID = dlt_ID;
            }

        }

        public class FacilityGroup
        {

            private int dlf_ID = -1;
            /// <summary>
            /// The ID of the facility group (from the dlf_ID column in the DL facilities table).
            /// </summary>
            public int Dlf_ID
            {
                get
                {
                    return dlf_ID;
                }
                set
                {
                    dlf_ID = value;
                }
            }

            public FacilityGroup()
            {
                Dlf_ID = -1;
            }

            public FacilityGroup(int dlf_ID)
            {
                Dlf_ID = dlf_ID;
            }

        }

        public class GeographyType
        {

            private int geogTypeID = -1;
            /// <summary>
            /// The ID of the geography type (from the dlg_ID PK column in the DL geographies table).
            /// </summary>
            public int GeogTypeID
            {
                get
                {
                    return geogTypeID;
                }
                set
                {
                    geogTypeID = value;
                }
            }

            public GeographyType()
            {
                GeogTypeID = -1;
            }

            public GeographyType(int geogTypeID)
            {
                GeogTypeID = geogTypeID;
            }

        }

        public class GeogTypeStatLayerPair
        {

            private int srcID = -1;
            /// <summary>
            /// The ID of the source record used to produce this object, if applicable.
            /// For example, this could be the CG ID if these were produced from a list
            /// of cg_stats to be used to filter the original list to those allowed.
            /// This ID can be used to tie these records back to the original records for
            /// selection/filtering purposes.
            /// </summary>
            public int SrcID
            {
                get
                {
                    return srcID;
                }
                set
                {
                    srcID = value;
                }
            }

            private int geogTypeID = -1;
            /// <summary>
            /// The ID of the geography type (from the dlg_ID PK column in the DL geographies table).
            /// </summary>
            public int GeogTypeID
            {
                get
                {
                    return geogTypeID;
                }
                set
                {
                    geogTypeID = value;
                }
            }

            private int statLayerID = -1;
            /// <summary>
            /// The ID of the statistic layer (from the dll_ID PK column in the DL layers table).
            /// </summary>
            public int StatLayerID
            {
                get
                {
                    return statLayerID;
                }
                set
                {
                    statLayerID = value;
                }
            }

            public GeogTypeStatLayerPair()
            {
                SrcID = -1;
                GeogTypeID = -1;
                StatLayerID = -1;
            }

            public GeogTypeStatLayerPair(int geogTypeID, int statLayerID)
            {
                SrcID = -1;
                GeogTypeID = geogTypeID;
                StatLayerID = statLayerID;
            }

            private bool isStatLayerOnly = false;
            /// <summary>
            /// Flag specifies if this object is intended to model a statistic only
            /// and not the geography component. Access checks on this object will ignore the geography
            /// permissions and only check the statistic layer access rights..
            /// </summary>
            public bool IsStatLayerOnly
            {
                get
                {
                    return isStatLayerOnly;
                }
                set
                {
                    isStatLayerOnly = value;
                }
            }

            private bool isGeogTypeOnly = false;
            /// <summary>
            /// Flag specifies if this object is intended to model a geography type only
            /// and not the statistic component. Access checks on this object will ignore the statistic
            /// permissions and only check the geography type access rights.
            /// </summary>
            public bool IsGeogTypeOnly
            {
                get
                {
                    return isGeogTypeOnly;
                }
                set
                {
                    isGeogTypeOnly = value;
                }
            }
        }

        #endregion

        #region Properties

        private ConfigurationInfo lcf = null;
        /// <summary>
        /// The configuration file for the secure content wrapper.
        /// Specifies which DB the security tables are in.
        /// </summary>
        public ConfigurationInfo Lcf
        {
            get
            {
                return lcf;
            }
            set
            {
                lcf = value;
            }
        }

        private AppSecurityContext appSecContext = null;
        /// <summary>
        /// The security context for the whole application.
        /// </summary>
        public AppSecurityContext AppSecContext
        {
            get
            {
                return appSecContext;
            }
            set
            {
                appSecContext = value;
            }
        }

        public UserSecurityContext currentUserSecurityContext = null;
        /// <summary>
        /// The security context of the User of the session.
        /// </summary>
        public UserSecurityContext CurrentUserSecurityContext
        {
            get
            {
                if (IsUsingStagingDB && currentUserSecurityContext == null)
                {
                    // If using the staging, then leave initialision of this until it is accesses here
                    CurrentUserSecurityContext = UserSecurityContext.GetCurrentUserSecurityContext(AppSecContext);
                }
                if (!IsUsingStagingDB && currentUserSecurityContext == null)
                {
                    Logger.LogWarning("Null CurrentUserSecurityContext accessed!");
                }

                return currentUserSecurityContext;
            }
            set
            {
                currentUserSecurityContext = value;
            }
        }

        public bool IsUseSecurityRules
        {
            get
            {
                return IS_USE_SECURITY_RULES;
            }
        }

        public bool isUseStaging = false;
        /// <summary>
        /// Flag indicates whether this is using the staging DB or not.
        /// </summary>
        public bool IsUsingStagingDB
        {
            get
            {
                return isUseStaging;
            }
            set
            {
                isUseStaging = value;
            }
        }

        #endregion

        #region Statics

        public static bool IS_USE_SECURITY_RULES
        {
            get
            {
                bool isUseSecurityRules = false;

                if (System.Configuration.ConfigurationManager.AppSettings[SecureContentWrapper.USE_SECURITY_RULES_APP_SETTING] != null)
                {
                    bool.TryParse(System.Configuration.ConfigurationManager.AppSettings[USE_SECURITY_RULES_APP_SETTING], out isUseSecurityRules);
                }

                return isUseSecurityRules;
            }
        }

        public static readonly string USE_SECURITY_RULES_APP_SETTING = "useSecurityRules";

        public static readonly string SECURITY_WRAPPER_LIVE_DB_SESSION_KEY = "SESSION_SECURITY_LIVE_DB_CONTENT_WRAPPER";

        public static readonly string SECURITY_WRAPPER_STAGING_DB_SESSION_KEY = "SESSION_SECURITY_STAGING_DB_CONTENT_WRAPPER";

        public static readonly string SECURITY_UPDATED_THIS_SESSION_KEY = "SECURITY_UPDATED_THIS_SESSION_KEY";

        public static SecureContentWrapper LiveDbContextInstance
        {
            get
            {
                SecureContentWrapper sessionSecurityWrapper = null;

                try
                {
                    if (HttpContext.Current.Session[SECURITY_WRAPPER_LIVE_DB_SESSION_KEY] == null)
                    {
                        sessionSecurityWrapper = new SecureContentWrapper();
                        HttpContext.Current.Session[SECURITY_WRAPPER_LIVE_DB_SESSION_KEY] = sessionSecurityWrapper;
                    }
                    else
                    {
                        sessionSecurityWrapper = HttpContext.Current.Session[SECURITY_WRAPPER_LIVE_DB_SESSION_KEY] as SecureContentWrapper;
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogError(5, "Error getting SecureContentWrapper.LiveDbContextInstance() at " + ex.StackTrace);
                    sessionSecurityWrapper = null;
                }

                return sessionSecurityWrapper;
            }
            set
            {
                HttpContext.Current.Session[SECURITY_WRAPPER_LIVE_DB_SESSION_KEY] = value;
            }
        }


        /// <summary>
        /// Because of the way the namespaces are setup its tricky to record changes to the
        /// secure user groups in the DataLayer.ChangeLog.
        ///
        /// The solution is to remember when there has been a change in the session using this parameters
        /// and check this everytime the MGLBasePage is called. Bit hacky but should work! :)
        /// </summary>
        public static bool SecurityHasBeenModifiedThisSession
        {
            get
            {
                bool securityHasBeenModifiedThisSession = false;

                try
                {
                    if (HttpContext.Current.Session[SECURITY_UPDATED_THIS_SESSION_KEY] == null)
                    {

                        HttpContext.Current.Session[SECURITY_UPDATED_THIS_SESSION_KEY] = securityHasBeenModifiedThisSession;
                    }
                    else
                    {
                        securityHasBeenModifiedThisSession = (bool)HttpContext.Current.Session[SECURITY_UPDATED_THIS_SESSION_KEY];
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogError(5, "Error getting SecureContentWrapper.SecurityHasBeenModifiedThisSession " + ex);
                    securityHasBeenModifiedThisSession = false;
                }

                return securityHasBeenModifiedThisSession;
            }
            set
            {
                HttpContext.Current.Session[SECURITY_UPDATED_THIS_SESSION_KEY] = value;
            }
        }

        //public static SecureContentWrapper StagingDbContextInstance
        //{
        //    get
        //    {
        //        SecureContentWrapper sessionSecurityWrapper = null;

        //        try
        //        {
        //            if (HttpContext.Current.Session[SECURITY_WRAPPER_STAGING_DB_SESSION_KEY] == null)
        //            {
        //                sessionSecurityWrapper = new SecureContentWrapper();
        //                HttpContext.Current.Session[SECURITY_WRAPPER_STAGING_DB_SESSION_KEY] = sessionSecurityWrapper;
        //            }
        //            else
        //            {
        //                sessionSecurityWrapper = HttpContext.Current.Session[SECURITY_WRAPPER_STAGING_DB_SESSION_KEY] as SecureContentWrapper;
        //            }
        //        }
        //        catch (Exception ex)
        //        {
        //            ILog slog = LogManager.GetLogger(typeof(SecureContentWrapper));
        //            sLogger.LogError("Error getting SecureContentWrapper.StagingDbContextInstance() at " + ex.StackTrace);
        //            sessionSecurityWrapper = null;
        //        }

        //        return sessionSecurityWrapper;
        //    }
        //    set
        //    {
        //        HttpContext.Current.Session[SECURITY_WRAPPER_STAGING_DB_SESSION_KEY] = value;
        //    }
        //}

        #endregion

        #region Constructors

        public SecureContentWrapper()
            : this(AppSecurityContext.MainDbLcf)
        {
            IsUsingStagingDB = false;
        }

        public SecureContentWrapper(bool isUseStaging)
        {
            IsUsingStagingDB = isUseStaging;
            if (IsUsingStagingDB)
                Initialise(AppSecurityContext.StagingDbLcf);
            else
                Initialise(AppSecurityContext.MainDbLcf);
        }

        /// <summary>
        /// Creates a new default SecurityContentWrapper.
        /// The default security context will be assumed.
        /// This is an ASP.NET web app with User/UserGroup/Content security rules.
        /// </summary>
        public SecureContentWrapper(ConfigurationInfo lcf)
        {
            if (lcf.DbConInfo.NAME.Equals(
                AppSecurityContext.StagingDbLcf.DbConInfo.NAME, StringComparison.CurrentCultureIgnoreCase))
            {
                IsUsingStagingDB = true;
            }
            else
            {
                IsUsingStagingDB = false;
            }

            Initialise(lcf);
        }

        private void Initialise(ConfigurationInfo lcf)
        {
            if (lcf == null)
            {
                string msg = "SecureContentWrapper detected NULL LCF in ctor!";
                Logger.LogError(5, msg);
                throw new Exception(msg);
            }

            Lcf = lcf;

            AppSecContext = new AppSecurityContext(lcf);

            if (!IsUsingStagingDB) // If using the staging, then leave CurrentUserSecurityContext null, and late bind it later
                CurrentUserSecurityContext = UserSecurityContext.GetCurrentUserSecurityContext(AppSecContext);
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Filters the supplied list of GeogType/StatLayer Pair objects returning a list of only those
        /// statistics that are allowed by the security context.
        /// Other descriptions of content (e.g. cg_statistic_desciption) can be translated (into GeogTypeStatLayerPair for example) using the ContentIdentityTranslator class.
        /// </summary>
        /// <param name="statDescs">A list of statistic objects to check access is allowed to.</param>
        /// <param name="reqContext">The context within which the request is being.</param>
        /// <returns>A list of only those statistics that are allowed by the security context.</returns>
        public List<GeogTypeStatLayerPair> GetAllowed(
            List<GeogTypeStatLayerPair> statDescs,
            SecureRequestContext requestContext)
        {
            if (!IsUseSecurityRules)
                return statDescs;

            List<GeogTypeStatLayerPair> allowedStatDescs = null;

            if (statDescs == null)
            {
                Logger.LogError(5, "Cannot filter a NULL list of stat descs!");
                return null;
            }
            else if (statDescs.Count == 0)
            {
                // Logger.LogWarning("Cannot filter an empty list of stat descs!");
                return statDescs;
            }

            allowedStatDescs = new List<GeogTypeStatLayerPair>();

            foreach (GeogTypeStatLayerPair stat in statDescs)
            {
                if (IsAllowed(stat, requestContext))
                    allowedStatDescs.Add(stat);
            }

            return allowedStatDescs;
        }

        public List<Report> GetAllowed(
            List<Report> reports,
            SecureRequestContext requestContext)
        {
            if (!IsUseSecurityRules)
                return reports;

            List<Report> allowedReports = null;

            if (reports == null)
            {
                Logger.LogError(5, "Cannot filter a NULL list of reports!");
                return reports;
            }
            else if (reports.Count == 0)
            {
                // Logger.LogWarning("Cannot filter an empty list of reports!");
                return reports;
            }

            allowedReports = new List<Report>();

            foreach (Report report in reports)
            {
                if (IsAllowed(report, requestContext))
                    allowedReports.Add(report);
            }

            return allowedReports;
        }

        /// <summary>
        /// Filters the supplied list of facility group objects returning a list of only those
        /// statistics that are allowed by the security context.
        /// Other descriptions of content (e.g. cg_facility_desciption) can be translated (into FacilityGroup for example) using the ContentIdentityTranslator class.
        /// </summary>
        /// <param name="statDescs">A list of FacilityGroup objects to check access is allowed to.</param>
        /// <param name="reqContext">The context within which the request is being.</param>
        /// <returns>A list of only those statistics that are allowed by the security context.</returns>
        public List<FacilityGroup> GetAllowed(
            List<FacilityGroup> facilityGroups,
            SecureRequestContext requestContext)
        {
            if (!IsUseSecurityRules)
                return facilityGroups;

            List<FacilityGroup> allowedFacilityGroups = null;

            if (facilityGroups == null)
            {
                Logger.LogError(5, "Cannot filter a NULL list of facilityGroups!");
                return null;
            }
            else if (facilityGroups.Count == 0)
            {
                // Logger.LogWarning("Cannot filter an empty list of facilityGroups!");
                return facilityGroups;
            }

            allowedFacilityGroups = new List<FacilityGroup>();

            foreach (FacilityGroup facilityGroup in facilityGroups)
            {
                if (IsAllowed(facilityGroup, requestContext))
                    allowedFacilityGroups.Add(facilityGroup);
            }

            return allowedFacilityGroups;
        }

        /// <summary>
        /// Filters the supplied list of theme objects returning a list of only those
        /// statistics that are allowed by the security context.
        /// Other descriptions of content (e.g. ThemeMenuNode) can be translated (into Theme for example) using the ContentIdentityTranslator class.
        /// </summary>
        /// <param name="themes">A list of Theme objects to check access is allowed to.</param>
        /// <param name="reqContext">The context within which the request is being.</param>
        /// <returns>A list of only those themes that are allowed by the security context.</returns>
        public List<Theme> GetAllowed(
            List<Theme> themes,
            SecureRequestContext requestContext)
        {
            if (!IsUseSecurityRules)
                return themes;

            List<Theme> allowedThemes = null;

            if (themes == null)
            {
                Logger.LogError(5, "Cannot filter a NULL list of Themes!");
                return null;
            }
            else if (themes.Count == 0)
            {
                // Logger.LogWarning("Cannot filter an empty list of Themes!");
                return themes;
            }

            allowedThemes = new List<Theme>();

            foreach (Theme theme in themes)
            {
                if (IsAllowed(theme, requestContext))
                    allowedThemes.Add(theme);
            }

            return allowedThemes;
        }

        //public bool IsAllowed(
        //   ZoomLevelInformation zli)
        //{
        //    SecureRequestContext requestContext = new SecureRequestContext(SecureRequestContext.DisplayType.MAP);
        //    return IsAllowed(zli, requestContext);
        //}

        //public bool IsAllowed(
        //    ZoomLevelInformation zli,
        //    SecureRequestContext requestContext)
        //{
        //    bool isAllowed = false;

        //    try
        //    {
        //        if (AppSecContext.ZoomLevelIdGeoTypeIdLookup == null ||
        //            AppSecContext.ZoomLevelIdGeoTypeIdLookup.Count < 1)
        //        {
        //            Logger.LogError("Cannot check if ZoomLevelInformation is allowed as ZoomLevelIdGeoTypeIdLookup is NULL or empty!");
        //            return false;
        //        }

        //        // 1. Get the dlg_ID from the application cache using the ZoomLevelInformation.ID:
        //        if (!AppSecContext.ZoomLevelIdGeoTypeIdLookup.ContainsKey(zli.ID))
        //        {
        //            // This zoom level is not in the dl_geographies table and therefore is not secured and not securable.
        //            return true;
        //        }

        //        // 2. Check if the dlg_ID access is allowed:
        //        GeogTypeStatLayerPair geogType = new GeogTypeStatLayerPair();
        //        geogType.GeogTypeID = AppSecContext.ZoomLevelIdGeoTypeIdLookup[zli.ID];
        //        geogType.IsGeogTypeOnly = true;

        //        isAllowed = IsAllowed(geogType, requestContext);
        //    }
        //    catch (Exception ex)
        //    {
        //        Logger.LogError("Problem checking if requested ZoomLevelInformation (ID = " + zli.ID + ") is allowed at " + ex);
        //        isAllowed = false;
        //    }

        //    return isAllowed;
        //}

        /// <summary>
        /// Checks if the CurrentUser is allowed to access the specified statistic (layer and geography type) in the requested context.
        /// </summary>
        /// <param name="stat">The statistic access is being requested for.</param>
        /// <param name="requestContext">The context of the access request (how the result will be displayed and where)</param>
        /// <returns>True, if the request is allowed, false otherwise.</returns>
        public bool IsAllowed(
            GeogTypeStatLayerPair stat,
            SecureRequestContext requestContext)
        {
            if (!IsUseSecurityRules)
                return true;

            bool isAllowed = false;

            if (stat == null)
            {
                Logger.LogError(5, "Access to a NULL stat desc cannot be allowed!");
                return false;
            }

            List<GroupPermissions> allowedGeoUserGroups = null;
            List<GroupPermissions> allowedLayerGroups = null;

            isAllowed =
                (stat.IsStatLayerOnly || IsContentAccessAllowed(stat.GeogTypeID, SecureRequestContext.ContentType.GEO_LAYER, out allowedGeoUserGroups)) &&
                (stat.IsGeogTypeOnly || IsContentAccessAllowed(stat.StatLayerID, SecureRequestContext.ContentType.STAT_LAYER, out allowedLayerGroups));

            if (isAllowed)
            {
                if (stat.IsStatLayerOnly && allowedLayerGroups != null && allowedLayerGroups.Count > 0)
                {
                    isAllowed = IsRequestContextAllowed(allowedLayerGroups, requestContext);
                }
                else if (stat.IsGeogTypeOnly && allowedGeoUserGroups != null && allowedGeoUserGroups.Count > 0)
                {
                    isAllowed = IsRequestContextAllowed(allowedGeoUserGroups, requestContext);
                }
                else if (!stat.IsStatLayerOnly && !stat.IsGeogTypeOnly)
                {
                    List<GroupPermissions> contentAllowedGroups = GetUserGroupsInCommon(allowedGeoUserGroups, allowedLayerGroups);

                    if (contentAllowedGroups == null || contentAllowedGroups.Count == 0)
                        isAllowed = false;
                    else
                    {
                        isAllowed = IsRequestContextAllowed(contentAllowedGroups, requestContext);
                    }
                }
            }

            return isAllowed;
        }

        /// <summary>
        /// Checks if the CurrentUser is allowed to access the specified report in the requested context.
        /// </summary>
        /// <param name="report">The report access is being requested for.</param>
        /// <param name="requestContext">The context of the access request (how the result will be displayed and where)</param>
        /// <returns>True, if the request is allowed, false otherwise.</returns>
        public bool IsAllowed(
            Report report,
            SecureRequestContext requestContext)
        {
            if (!IsUseSecurityRules)
                return true;

            bool isAllowed = false;

            if (report == null)
            {
                Logger.LogError(5, "Access to a NULL report cannot be allowed!");
                return false;
            }

            List<GroupPermissions> contentAllowedGroups = null;

            isAllowed =
                IsContentAccessAllowed(report.Report_ID, SecureRequestContext.ContentType.REPORT, out contentAllowedGroups);
            if (isAllowed)
            {
                isAllowed = IsRequestContextAllowed(contentAllowedGroups, requestContext);
            }

            return isAllowed;
        }

        /// <summary>
        /// Checks if the CurrentUser is allowed to access the specified layergroup in the requested context.
        /// </summary>
        /// <param name="layerGroup">The layerGroup access is being requested for.</param>
        /// <param name="requestContext">The context of the access request (how the result will be displayed and where)</param>
        /// <returns>True, if the request is allowed, false otherwise.</returns>
        public bool IsAllowed(
            LayerGroup layerGroup,
            SecureRequestContext requestContext)
        {
            if (!IsUseSecurityRules)
                return true;

            bool isAllowed = false;

            if (layerGroup == null)
            {
                Logger.LogError(5, "Access to a NULL layerGroup cannot be allowed!");
                return false;
            }

            List<GroupPermissions> contentAllowedGroups = null;

            isAllowed =
                IsContentAccessAllowed(layerGroup.LayerGroup_ID, SecureRequestContext.ContentType.STAT_LAYER_GROUP, out contentAllowedGroups);
            if (isAllowed)
            {
                isAllowed = IsRequestContextAllowed(contentAllowedGroups, requestContext);
            }

            return isAllowed;
        }

        /// <summary>
        /// Checks if the CurrentUser is allowed to access the specified facility group in the requested context.
        /// </summary>
        /// <param name="stat">The facility group access is being requested for.</param>
        /// <param name="requestContext">The context of the access request (how the result will be displayed and where)</param>
        /// <returns>True, if the request is allowed, false otherwise.</returns>
        public bool IsAllowed(
            FacilityGroup fac,
            SecureRequestContext requestContext)
        {
            if (!IsUseSecurityRules)
                return true;

            bool isAllowed = false;

            if (fac == null)
            {
                Logger.LogError(5, "Access to a NULL facilityGroup cannot be allowed!");
                return false;
            }

            List<GroupPermissions> contentAllowedGroups = null;

            isAllowed =
                IsContentAccessAllowed(fac.Dlf_ID, SecureRequestContext.ContentType.FACILITY_GROUP, out contentAllowedGroups);
            if (isAllowed)
            {
                isAllowed = IsRequestContextAllowed(contentAllowedGroups, requestContext);
            }

            return isAllowed;
        }

        /// <summary>
        /// Checks if the CurrentUser is allowed to access the specified theme in the requested context.
        /// </summary>
        /// <param name="theme">The theme access is being requested for.</param>
        /// <param name="requestContext">The context of the access request (how the result will be displayed and where)</param>
        /// <returns>True, if the request is allowed, false otherwise.</returns>
        public bool IsAllowed(
            Theme theme,
            SecureRequestContext requestContext)
        {
            if (!IsUseSecurityRules)
                return true;

            bool isAllowed = false;

            if (theme == null)
            {
                Logger.LogError(5, "Access to a NULL Theme cannot be allowed!");
                return false;
            }

            List<GroupPermissions> contentAllowedGroups = null;
            isAllowed =
                IsContentAccessAllowed(theme.Dlt_ID, SecureRequestContext.ContentType.THEME, out contentAllowedGroups);
            if (isAllowed)
            {
                isAllowed = IsRequestContextAllowed(contentAllowedGroups, requestContext);
            }

            return isAllowed;
        }

        public bool IsAllowed(
            SecureRequestContext requestContext)
        {
            if (!IsUseSecurityRules)
                return true;

            bool isAllowed = false;

            if (requestContext == null)
            {
                Logger.LogError(5, "Access to a NULL SecureRequestContext cannot be allowed!");
                return false;
            }

            if (!requestContext.IsSecurityContextDynamic)
            {
                isAllowed = IsRequestContextAllowed(CurrentUserSecurityContext.CurrentUserGroupPermissions, requestContext);
            }
            else
            {
                AppSecurityContext appSecContext = new AppSecurityContext(AppSecurityContext.StagingDbLcf);
                UserSecurityContext dynamicSecContext = UserSecurityContext.GetCurrentUserSecurityContext(appSecContext);
                isAllowed = IsRequestContextAllowed(dynamicSecContext.CurrentUserGroupPermissions, requestContext);
            }

            return isAllowed;
        }

        /// <summary>
        /// Checks if the CurrentUser is allowed the requested context.
        /// </summary>
        /// <param name="requestContext">The request context access is being checked for.</param>
        /// <returns>True, if the request is allowed, false otherwise.</returns>
        public bool IsAllowed(
            SecureRequestContext requestContext,
            UserSecurityContext secContext)
        {
            if (!IsUseSecurityRules)
                return true;

            bool isAllowed = false;

            if (requestContext == null)
            {
                Logger.LogError(5, "Access to a NULL SecureRequestContext cannot be allowed!");
                return false;
            }

            isAllowed = IsRequestContextAllowed(secContext.CurrentUserGroupPermissions, requestContext);

            return isAllowed;
        }

        public bool IsRequestContextAllowed(
            List<GroupPermissions> contentAllowedGroups,
            SecureRequestContext requestContext)
        {
            bool isRequestContextAllowed = false;

            if (!requestContext.IsSpecified)
            {   // If this is a request that has no security context at all, allow it.
                return true;
            }

            if (contentAllowedGroups == null || contentAllowedGroups.Count == 0)
                return false;

            if (requestContext == null)
                return false;

            foreach (GroupPermissions group in contentAllowedGroups)
            {
                bool displayModeAllowed = false;

                // TODO: change this to work like the functionality below:
                if (requestContext.DisplayMode == SecureRequestContext.DisplayType.UNKNOWN ||
                    IsContained(group.GroupDisplayPermissions, requestContext.DisplayMode))
                {
                    displayModeAllowed = true;
                }

                bool functionalityAllowed = false;

                if (requestContext.Functionality == SecureRequestContext.FunctionalityType.UNKNOWN ||
                    IsContained(group.GroupFunctionPermissions, requestContext.Functionality))
                {
                    functionalityAllowed = true;
                }

                if(displayModeAllowed && functionalityAllowed)
                {
                    isRequestContextAllowed = true;
                    break;
                }
            }

            return isRequestContextAllowed;
        }

        public bool IsContained(List<GroupPermissions.GroupFunctionalityPermission> groupPerms, SecureRequestContext.FunctionalityType functionType)
        {
            bool isContained = false;

            if (groupPerms == null || groupPerms.Count == 0)
            {
                return false;
            }

            try
	        {
                foreach (GroupPermissions.GroupFunctionalityPermission groupPerm in groupPerms)
                {
                    if (groupPerm.FunctionType == functionType)
                    {
                        return true;
                    }
                }
	        }
	        catch (Exception ex)
	        {
                Logger.LogError(5, "Problem checking if group functionality permission is contained in group perms list at " + ex);
                return false;
	        }

            return isContained;
        }

        public bool IsContained(List<GroupPermissions.GroupDisplayPermission> groupPerms, SecureRequestContext.DisplayType displayType)
        {
            bool isContained = false;

            if (groupPerms == null || groupPerms.Count == 0)
            {
                return false;
            }

            try
            {
                foreach (GroupPermissions.GroupDisplayPermission groupPerm in groupPerms)
                {
                    if (groupPerm.DisplayType == displayType)
                    {
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Problem checking if group display permission is contained in group perms list at " + ex);
                return false;
            }

            return isContained;
        }

        public bool IsContentAccessAllowed(
            int contentID,
            SecureRequestContext.ContentType contentType,
            out List<GroupPermissions> allowedUserGroups)
        {
            allowedUserGroups = null;

            if (!IsUseSecurityRules)
                return true;

            bool isAllowed = false;

            if (!IsContentIdValid(contentID))
                return false;

            allowedUserGroups = GetGroupsPermittedToContent(
                CurrentUserSecurityContext.CurrentUserGroupPermissions,
                contentID, contentType);

            isAllowed = (allowedUserGroups != null && allowedUserGroups.Count > 0);

            return isAllowed;
        }

        public List<GroupPermissions> GetGroupsPermittedToContent(
            List<GroupPermissions> userGroupsPermissions,
            int contentID, SecureRequestContext.ContentType contentType)
        {
            List<GroupPermissions> allowedUserGroups = null;

            if (userGroupsPermissions == null)
            {
                Logger.LogError(5, "NULL userGroupsPermissions detected, abandoning GetGroupsPermittedToContent ...");
                return null;
            }

            foreach (GroupPermissions usrGroupPerms in userGroupsPermissions)
            {
                if (usrGroupPerms == null)
                {
                    Logger.LogWarning("NULL usrGroupPerms detected, skiping it ...");
                    continue;
                }

                if (usrGroupPerms.GroupContentPermissions != null && usrGroupPerms.GroupContentPermissions.Count > 0)
                {
                    foreach (GroupPermissions.GroupContentPermission grpContentPerm in usrGroupPerms.GroupContentPermissions)
                    {
                        if (grpContentPerm.ContentType == contentType &&
                            grpContentPerm.ContentID > 0 &&
                            grpContentPerm.ContentID == contentID
                            )
                        {
                            if (allowedUserGroups == null)
                            {
                                allowedUserGroups = new List<GroupPermissions>();
                            }

                            allowedUserGroups.Add(usrGroupPerms);
                        }
                    }
                }
            }

            return allowedUserGroups;
        }

        #endregion

        #region Protected Methods

        protected bool IsContentIdValid(int contentID)
        {
            if (contentID < 1)
            {
                Logger.LogError(5, "Content ID is not a valid positive non-zero integer!");
                return false;
            }
            else
                return true;
        }

        protected bool IsUserGroupInCommon(List<GroupPermissions> userGroups1, List<GroupPermissions> userGroups2)
        {
            bool isUserGroupInCommon = false;

            if (userGroups1 == null || userGroups2 == null || userGroups1.Count == 0 || userGroups2.Count == 0)
                return false;

            foreach (GroupPermissions group1 in userGroups1)
            {
                if (group1 == null)
                    continue;

                foreach (GroupPermissions group2 in userGroups2)
                {
                    if (group2 == null)
                        continue;

                    if (group1.GroupID > 0 && group2.GroupID > 0 && group1.GroupID == group2.GroupID)
                        return true;
                }
            }

            return isUserGroupInCommon;
        }

        protected List<GroupPermissions> GetUserGroupsInCommon(List<GroupPermissions> userGroups1, List<GroupPermissions> userGroups2)
        {
            List<GroupPermissions> groupsInCommon = null;
            if (userGroups1 == null || userGroups2 == null || userGroups1.Count == 0 || userGroups2.Count == 0)
            {
                Logger.LogError(5, "Invalid input groups supplied to GetUserGroupsInCommon!");
                return null;
            }

            groupsInCommon = new List<GroupPermissions>();

            foreach (GroupPermissions group1 in userGroups1)
            {
                if (group1 == null)
                    continue;

                foreach (GroupPermissions group2 in userGroups2)
                {
                    if (group2 == null)
                        continue;

                    if (group1.GroupID > 0 && group2.GroupID > 0 && group1.GroupID == group2.GroupID)
                    {
                        if(!groupsInCommon.Contains(group1))
                            groupsInCommon.Add(group1);
                    }
                }
            }

            return groupsInCommon;
        }

        #endregion

        #region Static Vars

        public static readonly string ACCESS_DENIED_MSG = "Access Denied";

        #endregion

    }

}
