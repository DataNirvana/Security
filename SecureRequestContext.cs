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

using MGL.DomainModel;

namespace MGL.Security
{

    /// <summary>
    /// A class that models the context of a request for secure data.
    /// It specifies:
    /// How the information will be displayed (DisplayType).
    /// In what branch of functionality it will be displayed in.
    /// </summary>
    public class SecureRequestContext
    {

        #region Enums

        public enum ContentType
        {
            UNKNOWN = 0,
            STAT_LAYER,
            GEO_LAYER,
            THEME,
            FACILITY_GROUP,
            REPORT,
            STAT_LAYER_GROUP,
            SPATIALDATA, // Eddie 12 Oct 2011
            ADDRESS,  // Eddie 12 Oct 2011
            STREET  // Eddie 12 Oct 2011
        }

        public enum DisplayType
        {
            UNKNOWN = 0,
            MAP,
            TABLE,
            CHART,
            PRINT
        }

        public enum FunctionalityType
        {
            UNKNOWN = 0,
            WHAT_INFO,
            WHERES_MY_NEAREST,
            AREA_PROFILER,
            REPORT_ARCHIVE,
            REPORT_WIZARD,
            TIME_SERIES,
            DATA_DOWNLOAD,
            ADMIN,
            USER_ADMIN,
            DEPLOY,
            STAT_ADMIN,
            FACILITY_ADMIN,
            REPORT_ADMIN,
            THEME_ADMIN,
            USER_GROUP_ADMIN,
            BROWSE_THE_SYSTEM,
            PMT,
            DOWNLOAD_GEOCODED_INFO,
            UNSECURED,
            SPATIAL_ADMIN,
            DATA_FEED_ADMIN,
            DATA_LINK_ADMIN,
            ANALYSIS, // Eddie 12 Oct 2011
            BASE, // Eddie 12 Oct 2011
            ADMINISTRATION // Eddie 12 Oct 2011
        }

        /// <summary>
        /// Keep a list of the administrator functions so that we can highlight these
        /// in the UI
        ///
        /// </summary>
        public static List<FunctionalityType> AdministratorFunctions
        {
            get{
                List<FunctionalityType> result = new List<FunctionalityType>();

                result.Add(FunctionalityType.ADMIN);
                result.Add(FunctionalityType.DATA_FEED_ADMIN);
                result.Add(FunctionalityType.DATA_LINK_ADMIN);
                result.Add(FunctionalityType.DEPLOY);
                result.Add(FunctionalityType.FACILITY_ADMIN);
                result.Add(FunctionalityType.REPORT_ADMIN);
                result.Add(FunctionalityType.SPATIAL_ADMIN);
                result.Add(FunctionalityType.STAT_ADMIN);
                result.Add(FunctionalityType.THEME_ADMIN);
                result.Add(FunctionalityType.USER_ADMIN );
                result.Add(FunctionalityType.USER_GROUP_ADMIN);

                return result;
            }
        }

        #endregion

        #region Properties

        private bool isSecurityContextDynamic = false;
        /// <summary>
        /// The way the requested data will be displayed.
        /// </summary>
        public bool IsSecurityContextDynamic
        {
            get
            {
                return isSecurityContextDynamic;
            }
            set
            {
                isSecurityContextDynamic = value;
            }
        }

        private DisplayType displayMode = DisplayType.UNKNOWN;
        /// <summary>
        /// The way the requested data will be displayed.
        /// </summary>
        public DisplayType DisplayMode
        {
            get
            {
                return displayMode;
            }
            set
            {
                displayMode = value;
            }
        }

        private FunctionalityType functionality = FunctionalityType.UNKNOWN;
        /// <summary>
        /// The branch of functionality from which this request is being made.
        /// </summary>
        public FunctionalityType Functionality
        {
            get
            {
                return functionality;
            }
            set
            {
                functionality = value;
            }
        }

        public bool IsSpecified
        {
            get
            {
                if (DisplayMode != DisplayType.UNKNOWN || Functionality != FunctionalityType.UNKNOWN)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Creates a new empty SecureRequestContext.
        /// No information will be contained initially.
        /// </summary>
        public SecureRequestContext()
        {
            this.Functionality = FunctionalityType.UNKNOWN;
            this.DisplayMode = DisplayType.UNKNOWN;
        }

        public SecureRequestContext(FunctionalityType functionality)
        {
            this.Functionality = functionality;
            this.DisplayMode = DisplayType.UNKNOWN;
        }

        public SecureRequestContext(DisplayType displayMode)
        {
            this.DisplayMode = displayMode;
            this.Functionality = FunctionalityType.UNKNOWN;
        }

        public SecureRequestContext(FunctionalityType functionality, DisplayType displayMode)
        {
            this.Functionality = functionality;
            this.DisplayMode = displayMode;
        }

        #endregion

    }

}
