#pragma once

#include "surveillance_detector.h"
#include "adaptive_countermeasures.h"
#include <QtWidgets/QWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QSlider>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QFrame>
#include <QtWidgets/QTimer>
#include <QtCore/QPropertyAnimation>
#include <QtCharts/QChart>
#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>
#include <QtCharts/QValueAxis>
#include <memory>

QT_CHARTS_USE_NAMESPACE

namespace SpyGram::Counterintelligence {

/**
 * @brief Real-Time Counterintelligence Dashboard
 *
 * Provides comprehensive surveillance detection and countermeasure control:
 * - Real-time threat visualization and monitoring
 * - Manual and automatic countermeasure controls
 * - Hardware capability status and utilization
 * - Government mode interface for CAC/PIV operations
 * - Performance metrics and effectiveness analysis
 * - Emergency controls and rapid response interface
 */
class CounterIntelligenceDashboard : public QWidget {
    Q_OBJECT

public:
    explicit CounterIntelligenceDashboard(QWidget *parent = nullptr);
    ~CounterIntelligenceDashboard();

    // Integration with detection and countermeasure systems
    void setSurveillanceDetector(SurveillanceDetector *detector);
    void setAdaptiveCountermeasures(AdaptiveCountermeasures *countermeasures);

    // Dashboard modes
    void setGovernmentMode(bool enabled);
    void setExpertMode(bool enabled);

public slots:
    void showDashboard();
    void hideDashboard();
    void toggleDashboard();

private slots:
    // Threat monitoring
    void onThreatDetected(const ThreatAssessment &threat);
    void onThreatLevelChanged(ThreatLevel newLevel, ThreatLevel oldLevel);
    void updateThreatDisplay();

    // Countermeasure monitoring
    void onCountermeasureActivated(CountermeasureType type, CountermeasureIntensity intensity);
    void onCountermeasureDeactivated(CountermeasureType type);
    void onEmergencyModeActivated();
    void onEmergencyModeDeactivated();

    // Manual controls
    void onEmergencyButtonClicked();
    void onStopAllCountermeasuresClicked();
    void onSensitivityChanged(int value);
    void onMaxIntensityChanged(int index);
    void onAutomaticResponseToggled(bool enabled);

    // Hardware controls
    void onHardwareToggled();
    void updateHardwareStatus();

    // Display updates
    void updateRealTimeDisplay();
    void updatePerformanceMetrics();
    void updateEffectivenessChart();

private:
    // UI initialization
    void initializeUI();
    void createThreatMonitoringSection();
    void createCountermeasureControlSection();
    void createHardwareStatusSection();
    void createPerformanceSection();
    void createGovernmentModeSection();
    void createEmergencyControlsSection();

    // Visual updates
    void updateThreatLevelIndicator(ThreatLevel level);
    void updateCountermeasureIndicators();
    void updateHardwareIndicators();
    void animateThreatAlert(ThreatLevel level);

    // Utility functions
    QString getThreatLevelText(ThreatLevel level);
    QString getThreatLevelColor(ThreatLevel level);
    QString getCountermeasureTypeText(CountermeasureType type);
    QString getIntensityText(CountermeasureIntensity intensity);

    // Style management
    void applyDashboardStyling();
    void applyThreatLevelStyling(QWidget *widget, ThreatLevel level);

    // System integration
    SurveillanceDetector *_surveillance_detector = nullptr;
    AdaptiveCountermeasures *_adaptive_countermeasures = nullptr;

    // Dashboard modes
    bool _government_mode = false;
    bool _expert_mode = false;

    // Main layout
    std::unique_ptr<QVBoxLayout> _main_layout;

    // Threat monitoring section
    QGroupBox *_threat_section;
    QLabel *_threat_level_label;
    QLabel *_threat_level_indicator;
    QProgressBar *_threat_confidence_bar;
    QTextEdit *_threat_details_text;
    QLabel *_last_threat_time;
    QFrame *_threat_alert_frame;

    // Real-time threat chart
    QChart *_threat_chart;
    QChartView *_threat_chart_view;
    QLineSeries *_threat_level_series;
    QLineSeries *_confidence_series;
    QValueAxis *_time_axis;
    QValueAxis *_level_axis;

    // Countermeasure control section
    QGroupBox *_countermeasure_section;
    QLabel *_current_intensity_label;
    QSlider *_sensitivity_slider;
    QComboBox *_max_intensity_combo;
    QCheckBox *_automatic_response_checkbox;

    // Active countermeasures display
    QGridLayout *_countermeasure_grid;
    QHash<CountermeasureType, QLabel*> _countermeasure_indicators;
    QHash<CountermeasureType, QProgressBar*> _effectiveness_bars;

    // Hardware status section
    QGroupBox *_hardware_section;
    QCheckBox *_gna_checkbox;
    QCheckBox *_npu_checkbox;
    QCheckBox *_openvino_checkbox;
    QCheckBox *_audio_checkbox;
    QLabel *_hardware_performance_label;

    // Performance metrics section
    QGroupBox *_performance_section;
    QLabel *_detection_rate_label;
    QLabel *_average_response_time_label;
    QLabel *_countermeasure_effectiveness_label;
    QProgressBar *_system_load_bar;

    // Effectiveness chart
    QChart *_effectiveness_chart;
    QChartView *_effectiveness_chart_view;
    QHash<CountermeasureType, QLineSeries*> _effectiveness_series;

    // Government mode section
    QGroupBox *_government_section;
    QLabel *_government_status_label;
    QLabel *_cac_piv_status_label;
    QCheckBox *_government_mode_checkbox;
    QPushButton *_verify_credentials_button;

    // Emergency controls section
    QGroupBox *_emergency_section;
    QPushButton *_emergency_button;
    QPushButton *_stop_all_button;
    QLabel *_emergency_status_label;

    // Timers for real-time updates
    std::unique_ptr<QTimer> _display_update_timer;
    std::unique_ptr<QTimer> _chart_update_timer;
    std::unique_ptr<QTimer> _metrics_update_timer;

    // Animation system
    std::unique_ptr<QPropertyAnimation> _threat_alert_animation;

    // Data storage for charts
    QList<QPair<qint64, float>> _threat_level_history;
    QList<QPair<qint64, float>> _confidence_history;
    QHash<CountermeasureType, QList<QPair<qint64, float>>> _effectiveness_history;

    // Display parameters
    static constexpr int MAX_CHART_POINTS = 100;
    static constexpr int UPDATE_INTERVAL_MS = 1000;
    static constexpr int CHART_UPDATE_INTERVAL_MS = 5000;
    static constexpr int METRICS_UPDATE_INTERVAL_MS = 2000;
    static constexpr int THREAT_HISTORY_MINUTES = 10;
};

} // namespace SpyGram::Counterintelligence